"""Helpers for rendering and exporting scan reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.repositories.scans import ScanRepository
from app.utils.json_utils import safe_json_load, safe_json_load_dict, safe_json_load_list


def normalize_llm_report(raw_report: Any) -> Dict[str, str]:
    """Return a consistent general/technical report structure."""
    parsed = safe_json_load(raw_report, raw_report)
    if isinstance(parsed, dict):
        return {
            "general": str(parsed.get("general", "") or ""),
            "technical": str(parsed.get("technical", "") or ""),
            "rag": parsed.get("rag") if isinstance(parsed.get("rag"), dict) else {},
        }
    return {
        "general": str(raw_report or ""),
        "technical": "",
        "rag": {},
    }


def format_llm_report_text(report: Dict[str, str]) -> str:
    """Format report sections for Markdown and HTML exports."""
    sections = []
    general = (report.get("general") or "").strip()
    technical = (report.get("technical") or "").strip()
    rag = report.get("rag") if isinstance(report.get("rag"), dict) else {}

    if general:
        sections.append(f"General Assessment\n{general}")
    if technical:
        sections.append(f"Technical Assessment\n{technical}")
    if rag:
        threat_name = str(rag.get("threat_name") or "").strip()
        category = str(rag.get("category") or "").strip()
        confidence = rag.get("confidence", 0)
        mitre = rag.get("mitre", {}) if isinstance(rag.get("mitre"), dict) else {}
        if threat_name and threat_name.lower() != "unknown":
            sections.append(
                "RAG Threat Context\n"
                f"Primary match: {threat_name} ({category or 'Unknown category'})\n"
                f"Confidence: {confidence}%\n"
                f"MITRE ATT&CK: {mitre.get('id', 'Unknown')} - {mitre.get('name', 'Unknown')} ({mitre.get('tactic', 'Unknown')})"
            )

    return "\n\n".join(sections) if sections else "No AI assessment was available for this report."


@dataclass
class ReportContextBuilder:
    """Build view contexts from stored scan records."""

    scan_repository: ScanRepository

    def build_template_context(
        self,
        scan: Dict[str, Any],
        *,
        scan_id: int,
        user: Optional[Dict[str, Any]],
        is_cached: bool,
        request: Any,
    ) -> Dict[str, Any]:
        latest_request = None
        if user:
            latest_request = self.scan_repository.get_latest_request_for_scan(scan_id, user["id"])

        display_url = (
            (latest_request or {}).get("requested_url")
            or scan.get("original_input")
            or scan["url"]
        )

        return {
            "request": request,
            "url": display_url,
            "scan_target": scan["url"],
            "canonical_domain": scan.get("canonical_domain") or "",
            "analysis_mode": scan.get("analysis_mode") or "deep",
            "source_context": scan.get("source_context") or "website",
            "verdict": scan["verdict"],
            "risk_score": scan["risk_score"],
            "llm_report": normalize_llm_report(scan.get("llm_analysis")),
            "details": safe_json_load_dict(scan.get("raw_data")),
            "scan_id": scan_id,
            "user": user,
            "is_cached": bool(is_cached),
            "redirect_chain": safe_json_load_list(scan.get("redirect_chain")),
            "http_headers": safe_json_load_dict(scan.get("http_headers")),
            "page_meta": safe_json_load_dict(scan.get("page_meta")),
            "dom_stats": safe_json_load_dict(scan.get("dom_stats")),
            "server_info": safe_json_load_dict(scan.get("server_info")),
            "risk_breakdown": safe_json_load_list(scan.get("risk_breakdown")),
            "security_headers": safe_json_load_dict(scan.get("security_headers")),
            "security_headers_score": scan.get("security_headers_score", 0),
            "is_saved": self.scan_repository.is_scan_saved(
                scan_id,
                user["id"] if user else None,
            ),
        }
