"""
Helpers for browser-extension workflows.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.repositories import get_repository_container
from app.services.threat_intel import CONFIG, ShodanScanner, VirusTotalScanner
from app.utils.domain_utils import build_scan_url


QUICK_SCAN_CACHE_HOURS = 24
PORTS_CACHE_HOURS = 24
PAIRING_EXPIRY_MINUTES = 10
EXTENSION_SESSION_DAYS = 30


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _safe_json_load(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _contains_high_risk_category(categories: Any) -> bool:
    if not isinstance(categories, dict):
        return False

    risky_terms = ("phish", "malware", "malicious", "scam", "fraud")
    for value in categories.values():
        normalized = str(value or "").strip().lower()
        if any(term in normalized for term in risky_terms):
            return True
    return False


def map_quick_verdict(vt_result: Dict[str, Any]) -> tuple[str, int]:
    """Map VirusTotal-only results to the extension quick verdict."""
    malicious = int(vt_result.get("malicious_count", 0) or 0)
    suspicious = int(vt_result.get("suspicious_count", 0) or 0)
    harmless = int(vt_result.get("harmless_count", 0) or 0)
    undetected = int(vt_result.get("undetected_count", 0) or 0)
    total = int(vt_result.get("total_engines", 0) or 0)
    if total <= 0:
        total = malicious + suspicious + harmless + undetected

    reputation = int(vt_result.get("reputation", 0) or 0)
    has_high_risk_category = _contains_high_risk_category(vt_result.get("categories"))

    if malicious > 0:
        return "MALICIOUS", 95

    # A VT suspicious flag or strongly negative reputation is meaningful enough to
    # keep the extension cautious, but "no positive detections" should not block
    # common trusted websites.
    if suspicious > 0:
        return "SUSPICIOUS", 72

    if reputation <= -10 or has_high_risk_category:
        return "SUSPICIOUS", 68

    if total <= 0:
        return "SAFE", 15

    if harmless > 0:
        return "SAFE", 5

    if undetected > 0:
        return "SAFE", 12

    return "SAFE", 10


def is_ports_stale(timestamp_value: Optional[str], hours: int = PORTS_CACHE_HOURS) -> bool:
    ts = _parse_timestamp(timestamp_value)
    if not ts:
        return True
    return datetime.utcnow() - ts >= timedelta(hours=hours)


def build_extension_scan_payload(scan: Dict[str, Any], deep_scan_path: str) -> Dict[str, Any]:
    """Serialize a quick scan for extension clients."""
    repositories = get_repository_container()
    raw_data = _safe_json_load(scan.get("raw_data"), {})
    vt = raw_data.get("VirusTotal", {}) if isinstance(raw_data, dict) else {}
    analysis_mode = scan.get("analysis_mode") or "quick"

    verdict = (scan.get("verdict") or "SAFE").upper()
    risk_score = int(scan.get("risk_score") or 0)
    if analysis_mode == "quick" and isinstance(vt, dict):
        verdict, risk_score = map_quick_verdict(vt)

    local_ports = _safe_json_load(scan.get("open_ports"), [])
    latest_ports = None
    if not local_ports and scan.get("canonical_domain"):
        latest_ports = repositories.scans.get_latest_ports_for_domain(scan["canonical_domain"])

    effective_ports = local_ports
    ports_last_updated = scan.get("ports_last_updated")
    if not effective_ports and latest_ports:
        effective_ports = latest_ports.get("open_ports") or []
        ports_last_updated = latest_ports.get("ports_last_updated")

    return {
        "scan_id": scan["id"],
        "status": (scan.get("status") or "PENDING").lower(),
        "canonical_domain": scan.get("canonical_domain") or "",
        "original_input": scan.get("original_input") or scan.get("url") or "",
        "scan_target": scan.get("url") or "",
        "analysis_mode": analysis_mode,
        "verdict": verdict.lower(),
        "risk_score": risk_score,
        "virus_total": {
            "malicious_count": int(vt.get("malicious_count", 0) or 0),
            "suspicious_count": int(vt.get("suspicious_count", 0) or 0),
            "harmless_count": int(vt.get("harmless_count", 0) or 0),
            "undetected_count": int(vt.get("undetected_count", 0) or 0),
            "total_engines": int(vt.get("total_engines", 0) or 0),
            "detection_ratio": vt.get("detection_ratio") or "0/0",
            "last_analysis_date": vt.get("last_analysis_date"),
        },
        "open_ports": effective_ports or [],
        "ports_last_updated": ports_last_updated,
        "ports_refreshing": not effective_ports or is_ports_stale(ports_last_updated),
        "updated_at": scan.get("timestamp"),
        "deep_scan_path": deep_scan_path,
    }


async def refresh_ports_for_scan(scan_id: int, canonical_domain: str):
    """Refresh open-port enrichment without affecting the quick VT verdict."""
    repositories = get_repository_container()
    shodan_key = repositories.config.get_value("SHODAN_API_KEY") or CONFIG.shodan_key
    if not shodan_key:
        return

    scanner = ShodanScanner(shodan_key)
    try:
        result = await scanner.scan(build_scan_url(canonical_domain, "http"))
        ports = sorted(result.get("ports", [])) if isinstance(result, dict) else []
        repositories.scans.update_scan_ports(scan_id, ports)
    except Exception:
        # Keep quick scans resilient even when ports refresh fails.
        return


async def process_quick_scan_task(scan_id: int, canonical_domain: str):
    """Complete a VirusTotal-only quick scan for the browser extension."""
    start_time = time.time()
    repositories = get_repository_container()
    vt_key = repositories.config.get_value("VIRUSTOTAL_API_KEY") or CONFIG.virustotal_key
    scanner = VirusTotalScanner(vt_key)

    try:
        vt_result = await scanner.scan(build_scan_url(canonical_domain))
        verdict, risk_score = map_quick_verdict(vt_result if isinstance(vt_result, dict) else {})
        duration = round(time.time() - start_time, 2)

        repositories.scans.update_scan_results(
            scan_id=scan_id,
            verdict=verdict,
            risk_score=risk_score,
            raw_data={
                "VirusTotal": vt_result,
                "QuickScan": {
                    "canonical_domain": canonical_domain,
                    "verdict_source": "VirusTotal",
                },
            },
            llm_analysis=json.dumps({"general": "", "technical": ""}),
            redirect_chain=[],
            http_headers={},
            page_meta={"title": canonical_domain},
            dom_stats={},
            server_info={},
            risk_breakdown=[
                {
                    "source": "VirusTotal",
                    "base_risk": int(vt_result.get("risk_contribution", 0) or 0),
                    "weighted_risk": int(vt_result.get("risk_contribution", 0) or 0),
                }
            ],
            security_headers={},
            security_headers_score=0,
            scan_duration=duration,
            open_ports=None,
            ports_last_updated=None,
        )

        ports_meta = repositories.scans.get_latest_ports_for_domain(canonical_domain)
        if not ports_meta or is_ports_stale(ports_meta.get("ports_last_updated")):
            asyncio.create_task(refresh_ports_for_scan(scan_id, canonical_domain))
    except Exception as exc:
        duration = round(time.time() - start_time, 2)
        repositories.scans.update_scan_error(scan_id, str(exc), duration)
