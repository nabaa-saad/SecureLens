"""Threat-focused retrieval helpers backed by the bundled RAG assets."""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.core.config import get_config_value, get_settings


TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]{1,}")


MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "SOCIAL ENGINEERING ATTACKS": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
    },
    "MALWARE ATTACKS": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
    },
    "WEB APPLICATION ATTACKS": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "NETWORK ATTACKS": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
    },
    "AUTHENTICATION ATTACKS": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "CLOUD SECURITY THREATS": {
        "id": "T1526",
        "name": "Cloud Service Discovery",
        "tactic": "Discovery",
    },
    "CRYPTOGRAPHIC ATTACKS": {
        "id": "T1600",
        "name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "SUPPLY CHAIN ATTACKS": {
        "id": "T1195",
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
    },
    "INSIDER THREATS": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Persistence",
    },
    "DATA EXFILTRATION": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "COMMAND AND CONTROL": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
}


THREAT_HINTS: Dict[str, Dict[str, Any]] = {
    "PHISHING": {
        "category": "SOCIAL ENGINEERING ATTACKS",
        "tokens": (
            "login",
            "signin",
            "verify",
            "account",
            "credential",
            "password",
            "bank",
            "invoice",
            "update",
            "wallet",
            "otp",
        ),
    },
    "MALWARE": {
        "category": "MALWARE ATTACKS",
        "tokens": (
            "malware",
            "trojan",
            "payload",
            "dropper",
            "ransomware",
            "exploit",
            "backdoor",
            "rat",
            "loader",
        ),
    },
    "CROSS-SITE SCRIPTING (XSS)": {
        "category": "WEB APPLICATION ATTACKS",
        "tokens": (
            "xss",
            "cross-site scripting",
            "onerror",
            "<script",
            "javascript injection",
        ),
    },
    "SQL INJECTION": {
        "category": "WEB APPLICATION ATTACKS",
        "tokens": (
            "sql injection",
            "union select",
            "information_schema",
            "database error",
            "sql syntax",
        ),
    },
    "COMMAND INJECTION": {
        "category": "WEB APPLICATION ATTACKS",
        "tokens": (
            "command injection",
            "cmd.exe",
            "powershell",
            "/bin/sh",
            "shell",
        ),
    },
}


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _tokenize(text: str) -> List[str]:
    return TOKEN_RE.findall((text or "").lower())


def _summarize_entry(entry: Dict[str, Any]) -> str:
    return " ".join(
        part
        for part in [
            _normalize_text(entry.get("threat_name")),
            _normalize_text(entry.get("category")),
            _normalize_text(entry.get("definition")),
            _normalize_text(entry.get("attack_mechanism")),
            " ".join(_normalize_text(item) for item in entry.get("technical_indicators", [])[:6]),
            " ".join(_normalize_text(item) for item in entry.get("detection_methods", [])[:6]),
            " ".join(_normalize_text(item) for item in entry.get("keywords", [])[:8]),
        ]
        if part
    )


@lru_cache(maxsize=1)
def _load_knowledge_assets() -> Dict[str, Any]:
    settings = get_settings()
    base_dir = settings.project_root / "app" / "data" / "rag"
    kb_path = base_dir / "knowledge_base.json"

    knowledge_base: List[Dict[str, Any]] = []
    if kb_path.exists():
        knowledge_base = json.loads(kb_path.read_text(encoding="utf-8"))

    documents = []
    for entry in knowledge_base:
        documents.append(
            {
                "id": _normalize_text(entry.get("id")),
                "entry": entry,
                "summary": _summarize_entry(entry),
                "tokens": set(_tokenize(_summarize_entry(entry))),
            }
        )

    return {
        "base_dir": base_dir,
        "knowledge_base": knowledge_base,
        "documents": documents,
    }


@lru_cache(maxsize=1)
def _load_vector_backend() -> Dict[str, Any]:
    assets = _load_knowledge_assets()
    base_dir = assets["base_dir"]
    model_name = get_config_value("RAG", "EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    index_path = base_dir / "index.faiss"

    if not index_path.exists():
        return {"available": False, "error": "FAISS index file not found."}

    try:
        import faiss  # type: ignore
        import numpy as np  # type: ignore
        from sentence_transformers import SentenceTransformer  # type: ignore

        index = faiss.read_index(str(index_path))
        model = SentenceTransformer(model_name)
        return {
            "available": True,
            "faiss": faiss,
            "np": np,
            "index": index,
            "model": model,
            "model_name": model_name,
        }
    except Exception as exc:  # pragma: no cover - runtime environment dependent
        return {"available": False, "error": str(exc), "model_name": model_name}


class ThreatRAGService:
    """Hybrid vector or lexical retrieval over the bundled threat knowledge base."""

    def __init__(self) -> None:
        self.assets = _load_knowledge_assets()
        self.top_k = max(1, int(get_config_value("RAG", "TOP_K", "3") or "3"))

    def build_analysis(self, scan_data: Dict[str, Any], evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        evidence = evidence or {}
        query = self._build_query(scan_data, evidence)
        classification = self._classify(scan_data, evidence)
        matches, retrieval_mode = self._retrieve_matches(query, classification.get("threat_name"))

        primary = self._select_primary_match(matches, classification)
        mitre = self._map_mitre(primary.get("category"))
        iocs = self._extract_iocs(scan_data)
        recommendations = self._recommend_actions(scan_data, primary)
        analysis_summary = self._build_analysis_summary(scan_data, primary, classification)

        prompt_context = {
            "analysis_summary": analysis_summary,
            "primary_threat": {
                "threat_name": primary.get("threat_name", "Unknown"),
                "category": primary.get("category", "Unknown"),
                "confidence": primary.get("confidence", 0),
                "reasoning": primary.get("reasoning", []),
                "mitre": mitre,
            },
            "retrieved_knowledge": [
                {
                    "threat_name": match.get("threat_name"),
                    "category": match.get("category"),
                    "confidence": match.get("confidence"),
                    "definition": match.get("definition"),
                    "attack_mechanism": match.get("attack_mechanism"),
                    "technical_indicators": match.get("technical_indicators", [])[:4],
                    "detection_methods": match.get("detection_methods", [])[:4],
                    "real_world_impact": match.get("real_world_impact", ""),
                }
                for match in matches[: self.top_k]
            ],
            "iocs": iocs[:8],
            "recommendations": recommendations[:6],
        }

        return {
            "enabled": bool(self.assets.get("knowledge_base")),
            "retrieval_mode": retrieval_mode,
            "knowledge_base_entries": len(self.assets.get("knowledge_base", [])),
            "query": query,
            "analysis_summary": analysis_summary,
            "threat_name": primary.get("threat_name", "Unknown"),
            "category": primary.get("category", "Unknown"),
            "confidence": primary.get("confidence", 0),
            "reasoning": primary.get("reasoning", []),
            "mitre": mitre,
            "iocs": iocs,
            "recommended_actions": recommendations,
            "retrieved_documents": matches[: self.top_k],
            "prompt_context": prompt_context,
        }

    def _build_query(self, scan_data: Dict[str, Any], evidence: Dict[str, Any]) -> str:
        details = scan_data.get("details", {}) or {}
        vt = details.get("VirusTotal", {}) if isinstance(details, dict) else {}
        urlscan = details.get("URLScan", {}) if isinstance(details, dict) else {}
        deep = details.get("DeepContent", {}) if isinstance(details, dict) else {}
        whois = details.get("WHOIS", {}) if isinstance(details, dict) else {}
        page_meta = scan_data.get("page_meta", {}) or {}
        dom_stats = scan_data.get("dom_stats", {}) or {}
        security_headers = scan_data.get("security_headers", {}) or {}

        target_url = _normalize_text(scan_data.get("target_url") or scan_data.get("url"))
        hostname = evidence.get("target", {}).get("hostname") if isinstance(evidence, dict) else ""
        suspicious_terms = evidence.get("target", {}).get("suspicious_terms", []) if isinstance(evidence, dict) else []
        deep_signals = deep.get("signals", []) if isinstance(deep, dict) else []
        redirect_count = len(scan_data.get("redirect_chain", []) or [])
        missing_headers = [key for key, value in security_headers.items() if value == "Missing"]

        query_parts = [
            target_url,
            _normalize_text(hostname),
            _normalize_text(page_meta.get("title")),
            _normalize_text(page_meta.get("description")),
            f"verdict {scan_data.get('verdict', 'Unknown')}",
            f"risk score {scan_data.get('risk_score', 0)}",
            f"VirusTotal malicious {vt.get('malicious_count', 0)} suspicious {vt.get('suspicious_count', 0)}",
            f"redirect count {redirect_count}",
            f"URLScan malicious {bool(urlscan.get('malicious'))}",
            f"password inputs {dom_stats.get('password_inputs', 0)}",
            f"hidden inputs {dom_stats.get('hidden_inputs', 0)}",
            f"external scripts {len(dom_stats.get('external_scripts', []) or [])}",
            f"domain age {whois.get('domain_age_days', 'unknown')}",
            " ".join(_normalize_text(signal) for signal in deep_signals[:6]),
            " ".join(_normalize_text(term) for term in suspicious_terms[:8]),
            " ".join(missing_headers[:6]),
        ]
        return "\n".join(part for part in query_parts if part).strip()

    def _classify(self, scan_data: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
        details = scan_data.get("details", {}) or {}
        vt = details.get("VirusTotal", {}) if isinstance(details, dict) else {}
        urlscan = details.get("URLScan", {}) if isinstance(details, dict) else {}
        ssl_info = details.get("SSLCheck", {}) if isinstance(details, dict) else {}
        page_meta = scan_data.get("page_meta", {}) or {}
        dom_stats = scan_data.get("dom_stats", {}) or {}
        server_info = scan_data.get("server_info", {}) or {}
        redirect_chain = scan_data.get("redirect_chain", []) or []
        hostname = evidence.get("target", {}).get("hostname", "") if isinstance(evidence, dict) else ""
        suspicious_terms = evidence.get("target", {}).get("suspicious_terms", []) if isinstance(evidence, dict) else []

        if hostname in {"zero.webappsecurity.com", "testphp.vulnweb.com"}:
            return {
                "threat_name": "BENIGN TEST SITE",
                "category": "SAFE ENVIRONMENT",
                "confidence": 99,
                "reasoning": ["Known security training domain detected."],
            }

        signals_text = " ".join(
            [
                _normalize_text(page_meta.get("title")),
                _normalize_text(page_meta.get("description")),
                _normalize_text(server_info.get("server")),
                " ".join(_normalize_text(item) for item in (details.get("DeepContent", {}) or {}).get("signals", [])[:8]),
                " ".join(_normalize_text(item) for item in suspicious_terms),
                " ".join(_normalize_text(engine.get("result")) for engine in vt.get("malicious_engines", [])[:8] if isinstance(engine, dict)),
            ]
        ).lower()

        scores: Dict[str, int] = {}
        reasons: Dict[str, List[str]] = {}

        def add_signal(threat_name: str, points: int, reason: str) -> None:
            scores[threat_name] = scores.get(threat_name, 0) + points
            reasons.setdefault(threat_name, []).append(reason)

        vt_malicious = int(vt.get("malicious_count", 0) or 0)
        vt_suspicious = int(vt.get("suspicious_count", 0) or 0)
        password_inputs = int(dom_stats.get("password_inputs", 0) or 0)
        redirect_hosts = {
            (urlparse(str(hop.get("url") or "")).hostname or "").lower()
            for hop in redirect_chain
            if isinstance(hop, dict)
        }
        ssl_status = _normalize_text(ssl_info.get("status")).lower()

        if vt_malicious >= 5:
            add_signal("MALWARE", 34, f"VirusTotal reported {vt_malicious} malicious detections.")
        elif vt_malicious > 0:
            add_signal("MALWARE", 18, f"VirusTotal reported {vt_malicious} malicious detections.")

        if bool(urlscan.get("malicious")):
            add_signal("MALWARE", 16, "URLScan marked the target as malicious.")

        if password_inputs > 0:
            add_signal("PHISHING", 18, "The page exposes password input fields.")

        if any(term in signals_text for term in THREAT_HINTS["PHISHING"]["tokens"]):
            add_signal("PHISHING", 16, "The address and page content contain credential-collection language.")

        if len(redirect_hosts) > 1:
            add_signal("PHISHING", 10, "The redirect chain crosses multiple hosts.")

        if "invalid" in ssl_status or "expired" in ssl_status:
            add_signal("PHISHING", 8, "The certificate health looks suspicious for a login-oriented page.")

        if any(token in signals_text for token in THREAT_HINTS["CROSS-SITE SCRIPTING (XSS)"]["tokens"]):
            add_signal("CROSS-SITE SCRIPTING (XSS)", 26, "The scan output references likely script-injection indicators.")

        if any(token in signals_text for token in THREAT_HINTS["SQL INJECTION"]["tokens"]):
            add_signal("SQL INJECTION", 26, "The scan output references SQL-injection style strings.")

        if any(token in signals_text for token in THREAT_HINTS["COMMAND INJECTION"]["tokens"]):
            add_signal("COMMAND INJECTION", 26, "The scan output references shell or command-execution indicators.")

        if vt_suspicious > 0 and not scores:
            add_signal("PHISHING", 8, f"VirusTotal reported {vt_suspicious} suspicious detections.")

        if not scores:
            return {
                "threat_name": None,
                "category": None,
                "confidence": 0,
                "reasoning": [],
            }

        threat_name, score = max(scores.items(), key=lambda item: item[1])
        category = THREAT_HINTS.get(threat_name, {}).get("category")
        confidence = min(95, 35 + score)
        return {
            "threat_name": threat_name,
            "category": category,
            "confidence": confidence,
            "reasoning": reasons.get(threat_name, []),
        }

    def _retrieve_matches(
        self,
        query: str,
        classified_threat: Optional[str],
    ) -> Tuple[List[Dict[str, Any]], str]:
        vector_backend = _load_vector_backend()
        if vector_backend.get("available"):
            matches = self._vector_search(query, classified_threat, vector_backend)
            if matches:
                return matches, "vector"

        return self._lexical_search(query, classified_threat), "lexical"

    def _vector_search(
        self,
        query: str,
        classified_threat: Optional[str],
        backend: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        documents = self.assets.get("documents", [])
        if not documents:
            return []

        model = backend["model"]
        index = backend["index"]
        np = backend["np"]
        search_queries = [query]
        if classified_threat:
            search_queries.append(classified_threat)

        raw_results: Dict[int, Dict[str, Any]] = {}
        for search_query in search_queries:
            vector = model.encode([search_query])
            vector = np.asarray(vector, dtype="float32")
            distances, indices = index.search(vector, min(max(self.top_k * 2, 4), len(documents)))
            for rank, doc_index in enumerate(indices[0]):
                if int(doc_index) < 0 or int(doc_index) >= len(documents):
                    continue
                distance = float(distances[0][rank])
                doc = documents[int(doc_index)]["entry"]
                bonus = 0.0
                if classified_threat and _normalize_text(doc.get("threat_name")).upper() == classified_threat.upper():
                    bonus += 0.18
                similarity = max(0.0, 1.0 / (1.0 + distance) + bonus)
                stored = raw_results.get(int(doc_index))
                if stored is None or similarity > stored["score"]:
                    raw_results[int(doc_index)] = {
                        "entry": doc,
                        "score": similarity,
                    }

        ordered = sorted(raw_results.values(), key=lambda item: item["score"], reverse=True)
        return [self._serialize_match(item["entry"], item["score"]) for item in ordered[: self.top_k]]

    def _lexical_search(self, query: str, classified_threat: Optional[str]) -> List[Dict[str, Any]]:
        documents = self.assets.get("documents", [])
        if not documents:
            return []

        query_tokens = set(_tokenize(query))
        results = []
        for document in documents:
            entry = document["entry"]
            entry_tokens = document["tokens"]
            overlap = len(query_tokens & entry_tokens)
            keyword_bonus = 0
            for keyword in entry.get("keywords", [])[:8]:
                lowered = _normalize_text(keyword).lower()
                if lowered and lowered in query.lower():
                    keyword_bonus += 4

            exact_bonus = 0
            if classified_threat and _normalize_text(entry.get("threat_name")).upper() == classified_threat.upper():
                exact_bonus = 15

            score = overlap * 2 + keyword_bonus + exact_bonus
            if score <= 0:
                continue

            normalized = min(0.99, score / max(12.0, math.sqrt(len(entry_tokens) or 1) * 6.0))
            results.append(self._serialize_match(entry, normalized))

        results.sort(key=lambda item: item["score"], reverse=True)
        return results[: self.top_k]

    def _serialize_match(self, entry: Dict[str, Any], score: float) -> Dict[str, Any]:
        confidence = max(10, min(98, int(round(score * 100))))
        return {
            "id": _normalize_text(entry.get("id")),
            "threat_name": _normalize_text(entry.get("threat_name")) or "Unknown",
            "category": _normalize_text(entry.get("category")) or "Unknown",
            "score": round(score, 4),
            "confidence": confidence,
            "definition": _normalize_text(entry.get("definition")),
            "attack_mechanism": _normalize_text(entry.get("attack_mechanism")),
            "technical_indicators": [str(item) for item in entry.get("technical_indicators", [])[:6]],
            "detection_methods": [str(item) for item in entry.get("detection_methods", [])[:6]],
            "keywords": [str(item) for item in entry.get("keywords", [])[:8]],
            "risk_level_logic": _normalize_text(entry.get("risk_level_logic")),
            "real_world_impact": _normalize_text(entry.get("real_world_impact")),
            "reasoning": [],
        }

    def _select_primary_match(
        self,
        matches: List[Dict[str, Any]],
        classification: Dict[str, Any],
    ) -> Dict[str, Any]:
        classified_name = _normalize_text(classification.get("threat_name")).upper()
        for match in matches:
            if classified_name and _normalize_text(match.get("threat_name")).upper() == classified_name:
                merged = dict(match)
                merged["confidence"] = max(match.get("confidence", 0), classification.get("confidence", 0))
                merged["reasoning"] = classification.get("reasoning", [])
                return merged

        if classification.get("threat_name") and classification.get("category"):
            return {
                "id": "",
                "threat_name": classification["threat_name"],
                "category": classification["category"],
                "confidence": classification.get("confidence", 0),
                "score": round(classification.get("confidence", 0) / 100.0, 4),
                "definition": "",
                "attack_mechanism": "",
                "technical_indicators": [],
                "detection_methods": [],
                "keywords": [],
                "risk_level_logic": "",
                "real_world_impact": "",
                "reasoning": classification.get("reasoning", []),
            }

        if matches:
            primary = dict(matches[0])
            primary["reasoning"] = primary.get("reasoning", []) or [
                f"Retrieved as the closest threat-knowledge match with {primary.get('confidence', 0)} confidence."
            ]
            return primary

        return {
            "threat_name": "Unknown",
            "category": "Unknown",
            "confidence": 0,
            "reasoning": ["No close threat-knowledge match was available."],
        }

    def _map_mitre(self, category: Optional[str]) -> Dict[str, str]:
        category_key = _normalize_text(category).upper()
        mapped = MITRE_MAPPING.get(category_key)
        if mapped:
            return mapped
        return {"id": "Unknown", "name": "Unknown", "tactic": "Unknown"}

    def _extract_iocs(self, scan_data: Dict[str, Any]) -> List[Dict[str, str]]:
        details = scan_data.get("details", {}) or {}
        vt = details.get("VirusTotal", {}) if isinstance(details, dict) else {}
        geo = details.get("GeoIP", {}) if isinstance(details, dict) else {}
        shodan = details.get("Shodan", {}) if isinstance(details, dict) else {}
        cves = (details.get("CVEAnalysis", {}) or {}).get("vulnerabilities", []) if isinstance(details, dict) else []

        iocs: List[Dict[str, str]] = []
        target_url = _normalize_text(scan_data.get("target_url") or scan_data.get("url"))
        if target_url:
            iocs.append({"type": "URL", "value": target_url})

        ip_address = _normalize_text(shodan.get("ip") or geo.get("ip"))
        if ip_address:
            iocs.append({"type": "IP", "value": ip_address})

        country = _normalize_text(geo.get("country"))
        if country:
            iocs.append({"type": "Hosting Country", "value": country})

        malicious_count = int(vt.get("malicious_count", 0) or 0)
        if malicious_count > 0:
            iocs.append({"type": "VirusTotal Detections", "value": str(malicious_count)})

        for hop in (scan_data.get("redirect_chain", []) or [])[:4]:
            if not isinstance(hop, dict):
                continue
            hop_url = _normalize_text(hop.get("url"))
            if hop_url:
                iocs.append({"type": "Redirect", "value": hop_url})

        for cve in cves[:4]:
            if not isinstance(cve, dict):
                continue
            cve_id = _normalize_text(cve.get("id"))
            if cve_id:
                iocs.append({"type": "CVE", "value": cve_id})

        return iocs

    def _recommend_actions(self, scan_data: Dict[str, Any], primary: Dict[str, Any]) -> List[str]:
        recommendations = []
        risk_score = int(scan_data.get("risk_score", 0) or 0)
        threat_name = _normalize_text(primary.get("threat_name")).upper()
        dom_stats = scan_data.get("dom_stats", {}) or {}
        password_inputs = int(dom_stats.get("password_inputs", 0) or 0)
        redirect_count = len(scan_data.get("redirect_chain", []) or [])

        if risk_score >= 70:
            recommendations.append("Block or sandbox the address until an analyst validates the destination.")
        elif risk_score >= 40:
            recommendations.append("Treat the address as suspicious and verify business justification before opening it.")
        else:
            recommendations.append("Keep monitoring for changes because the current evidence is limited or mixed.")

        if threat_name == "PHISHING" or password_inputs > 0:
            recommendations.append("Do not submit credentials, MFA codes, or payment information to the page.")

        if threat_name == "MALWARE":
            recommendations.append("Prevent file downloads from the site and inspect endpoint telemetry for related execution attempts.")

        if redirect_count > 1:
            recommendations.append("Review each redirect hop and confirm that every host is expected and owned by the same entity.")

        recommendations.append("Correlate the hostname, certificate, and registrar information with trusted internal asset records.")
        return recommendations[:5]

    def _build_analysis_summary(
        self,
        scan_data: Dict[str, Any],
        primary: Dict[str, Any],
        classification: Dict[str, Any],
    ) -> str:
        details = scan_data.get("details", {}) or {}
        vt = details.get("VirusTotal", {}) if isinstance(details, dict) else {}
        ssl_info = details.get("SSLCheck", {}) if isinstance(details, dict) else {}
        geo = details.get("GeoIP", {}) if isinstance(details, dict) else {}
        threat_name = primary.get("threat_name", "Unknown")
        category = primary.get("category", "Unknown")

        lines = [
            f"URL analyzed: {_normalize_text(scan_data.get('target_url') or scan_data.get('url') or 'Unknown')}",
            f"Verdict: {_normalize_text(scan_data.get('verdict') or 'Unknown')}",
            f"Risk score: {scan_data.get('risk_score', 0)}/100",
            f"Primary threat hypothesis: {threat_name} ({category})",
            f"VirusTotal malicious detections: {vt.get('malicious_count', 0)}",
            f"SSL status: {_normalize_text(ssl_info.get('status') or 'Unknown')}",
            f"Hosting country: {_normalize_text(geo.get('country') or 'Unknown')}",
            f"Redirect count: {len(scan_data.get('redirect_chain', []) or [])}",
        ]
        if classification.get("reasoning"):
            lines.append("Reasoning: " + " ".join(classification["reasoning"][:3]))
        return "\n".join(lines)
