"""Scan lifecycle and orchestration helpers."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.core.logger import event_logger
from app.repositories.scans import ScanRepository
from app.services.llm_service import LLMReporter
from app.services.threat_intel import AnalysisEngine


@dataclass
class ScanResolution:
    """Describe how a scan request was resolved."""

    kind: str
    scan_id: int
    cached: bool = False


async def process_scan_task(scan_id: int, scan_url: str, scan_repository: Optional[ScanRepository] = None):
    """Run the full analysis pipeline for a shared deep scan row."""
    repository = scan_repository
    if repository is None:
        from app.utils.dependencies import get_scan_repository

        repository = get_scan_repository()

    start_time = time.time()

    try:
        async def report_progress(stage: str, step: int, message: str, percent: int):
            repository.update_scan_progress(
                scan_id,
                stage=stage,
                step=step,
                message=message,
                percent=percent,
            )

        engine = AnalysisEngine(repository.db)
        await report_progress("fetching", 1, "Preparing the staged analysis pipeline...", 5)
        res = await engine.analyze_url(scan_url, progress_callback=report_progress)

        ai_report = {
            "general": "Policy-enforced result: this scan was resolved by a governance rule.",
            "technical": "No AI report was generated because the domain matched a whitelist or blacklist rule.",
        }

        if "Governance" not in res["details"]:
            try:
                await report_progress("ai_analysis", 3, "Generating the AI-backed security summary...", 88)
                ai_report = await LLMReporter().generate_report_package(res)
            except Exception as exc:
                ai_report = {
                    "general": "AI report generation was unavailable, so a fallback summary was used.",
                    "technical": str(exc),
                    "rag": {},
                }

        duration = round(time.time() - start_time, 2)
        repository.update_scan_results(
            scan_id=scan_id,
            verdict=res["verdict"],
            risk_score=res["risk_score"],
            raw_data=res["details"],
            llm_analysis=json.dumps(ai_report),
            redirect_chain=res["redirect_chain"],
            http_headers=res["http_headers"],
            page_meta=res["page_meta"],
            dom_stats=res["dom_stats"],
            server_info=res["server_info"],
            risk_breakdown=res.get("risk_breakdown", []),
            security_headers=res.get("security_headers", {}),
            security_headers_score=res.get("security_headers_score", 0),
            scan_duration=duration,
            open_ports=(res.get("details", {}).get("Shodan", {}) or {}).get("ports", []),
        )
        event_logger.log_scan_complete(scan_id, res["verdict"], res["risk_score"], duration)
    except Exception as exc:
        duration = round(time.time() - start_time, 2)
        repository.update_scan_error(scan_id, str(exc), duration)
        event_logger.log_scan_failed(scan_id, str(exc))


@dataclass
class ScanFlowService:
    """Handle scan reuse, progress payloads, and persistence coordination."""

    scan_repository: ScanRepository

    def resolve_deep_scan(
        self,
        *,
        scan_url: str,
        requested_url: str,
        canonical_domain: str,
        user_id: Optional[int],
        source_context: str = "website",
        cache_hours: int = 24,
    ) -> ScanResolution:
        cached = self.scan_repository.get_cached_scan_by_domain(
            canonical_domain,
            analysis_mode="deep",
            hours_valid=cache_hours,
        )
        if cached:
            if user_id is not None:
                self.scan_repository.create_scan_request(
                    cached["id"],
                    user_id,
                    requested_url,
                    canonical_domain,
                    source_context,
                )
            return ScanResolution(kind="cached", scan_id=cached["id"], cached=True)

        pending = self.scan_repository.get_pending_scan_by_domain(
            canonical_domain,
            analysis_mode="deep",
        )
        if pending:
            if user_id is not None:
                self.scan_repository.create_scan_request(
                    pending["id"],
                    user_id,
                    requested_url,
                    canonical_domain,
                    source_context,
                )
            return ScanResolution(kind="pending", scan_id=pending["id"])

        scan_id = self.scan_repository.create_pending_scan(
            scan_url,
            user_id=user_id,
            canonical_domain=canonical_domain,
            original_input=requested_url,
            analysis_mode="deep",
            source_context=source_context,
        )
        if user_id is not None:
            self.scan_repository.create_scan_request(
                scan_id,
                user_id,
                requested_url,
                canonical_domain,
                source_context,
            )
        return ScanResolution(kind="new", scan_id=scan_id)

    def build_status_payload(self, scan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Build the JSON payload for live scan status checks."""
        if not scan:
            return {"status": "UNKNOWN"}

        status = scan.get("status")
        if status == "COMPLETED":
            return {
                "status": "COMPLETED",
                "redirect": f"/report/{scan['id']}",
                "progress_stage": scan.get("progress_stage") or "completed",
                "progress_step": scan.get("progress_step") or 4,
                "progress_message": scan.get("progress_message") or "Scan completed successfully.",
                "progress_percent": scan.get("progress_percent") or 100,
            }
        if status == "FAILED":
            return {
                "status": "FAILED",
                "progress_stage": scan.get("progress_stage") or "failed",
                "progress_step": scan.get("progress_step") or 4,
                "progress_message": scan.get("progress_message") or "Scan failed.",
                "progress_percent": scan.get("progress_percent") or 100,
            }
        return {
            "status": "PENDING",
            "progress_stage": scan.get("progress_stage") or "queued",
            "progress_step": scan.get("progress_step") or 1,
            "progress_message": scan.get("progress_message") or "Preparing the staged analysis pipeline...",
            "progress_percent": scan.get("progress_percent") or 3,
        }
