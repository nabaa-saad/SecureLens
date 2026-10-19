"""
LLM Service - Multi-provider AI integration for security analysis
Supports Ollama (local), OpenAI GPT, and Google Gemini
"""

import json
import re
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.core.config import get_config_value
from app.services.rag_service import ThreatRAGService
from app.utils.dependencies import get_config_repository


class AIProvider(Enum):
    """Supported AI providers"""
    OLLAMA = "ollama"
    OLLAMA_CLOUD = "ollama_cloud"
    OPENAI = "openai"
    GEMINI = "gemini"


class LLMReporter:
    """Multi-provider LLM service for generating security reports and chat"""
    
    def __init__(self):
        runtime_values = self._load_runtime_values()
        self.rag_service = ThreatRAGService()

        # Ollama config
        self.ollama_api = runtime_values["ollama_api"]
        self.ollama_model = runtime_values["ollama_model"]
        self.ollama_cloud_api = runtime_values["ollama_cloud_api"]
        self.ollama_cloud_api_key = runtime_values["ollama_cloud_api_key"]
        self.ollama_cloud_model = runtime_values["ollama_cloud_model"]
        
        # OpenAI config
        self.openai_api_key = runtime_values["openai_api_key"]
        self.openai_model = runtime_values["openai_model"]
        
        # Gemini config
        self.gemini_api_key = runtime_values["gemini_api_key"]
        self.gemini_model = runtime_values["gemini_model"]
        
        # Default provider
        self.default_provider = self.normalize_provider(runtime_values["default_provider"])
        
        # Legacy properties for backward compatibility
        self.api = self.ollama_api
        self.model = self.ollama_model

    def _load_runtime_values(self) -> Dict[str, str]:
        """Load assistant settings from DB first, then fall back to config.ini."""
        config_repository = None
        try:
            config_repository = get_config_repository()
        except Exception:
            config_repository = None

        def get_value(db_key: str, section: str, option: str, fallback: str = "") -> str:
            if config_repository is not None:
                db_value = config_repository.get_value(db_key)
                if db_value:
                    return db_value.strip()
            return get_config_value(section, option, fallback)

        return {
            "ollama_api": get_value("OLLAMA_API_URL", "OLLAMA", "API_URL", "http://localhost:11434/api/generate"),
            "ollama_model": get_value("OLLAMA_MODEL_NAME", "OLLAMA", "MODEL_NAME", "llama3.2"),
            "ollama_cloud_api": get_value("OLLAMA_CLOUD_API_URL", "OLLAMA_CLOUD", "API_URL", "https://ollama.com/api/chat"),
            "ollama_cloud_api_key": get_value("OLLAMA_CLOUD_API_KEY", "OLLAMA_CLOUD", "API_KEY", ""),
            "ollama_cloud_model": get_value("OLLAMA_CLOUD_MODEL_NAME", "OLLAMA_CLOUD", "MODEL_NAME", "gpt-oss:20b"),
            "openai_api_key": get_value("OPENAI_API_KEY", "OPENAI", "API_KEY", ""),
            "openai_model": get_value("OPENAI_MODEL_NAME", "OPENAI", "MODEL_NAME", "gpt-5.2"),
            "gemini_api_key": get_value("GEMINI_API_KEY", "GEMINI", "API_KEY", ""),
            "gemini_model": get_value("GEMINI_MODEL_NAME", "GEMINI", "MODEL_NAME", "gemini-2.5-flash"),
            "default_provider": get_value("AI_CHAT_DEFAULT_PROVIDER", "AI_CHAT", "DEFAULT_PROVIDER", "ollama"),
        }

    def normalize_provider(self, provider: Optional[str]) -> str:
        """Normalize provider names to supported values."""
        candidate = (provider or "").strip().lower()
        if candidate in {
            AIProvider.OPENAI.value,
            AIProvider.GEMINI.value,
            AIProvider.OLLAMA.value,
            AIProvider.OLLAMA_CLOUD.value,
        }:
            return candidate
        return AIProvider.OLLAMA.value

    def get_provider_status(self) -> Dict[str, Dict[str, Any]]:
        """Return provider availability and active model metadata."""
        return {
            AIProvider.OLLAMA.value: {
                "id": AIProvider.OLLAMA.value,
                "name": "Ollama",
                "display_name": "Ollama (Local)",
                "model": self.ollama_model,
                "available": bool(self.ollama_api),
                "reason": "",
            },
            AIProvider.OLLAMA_CLOUD.value: {
                "id": AIProvider.OLLAMA_CLOUD.value,
                "name": "Ollama Cloud",
                "display_name": "Ollama Cloud",
                "model": self.ollama_cloud_model,
                "available": bool(self.ollama_cloud_api_key),
                "reason": "" if self.ollama_cloud_api_key else "Ollama Cloud API key not configured",
            },
            AIProvider.OPENAI.value: {
                "id": AIProvider.OPENAI.value,
                "name": "OpenAI GPT",
                "display_name": "OpenAI GPT",
                "model": self.openai_model,
                "available": bool(self.openai_api_key),
                "reason": "" if self.openai_api_key else "OpenAI API key not configured",
            },
            AIProvider.GEMINI.value: {
                "id": AIProvider.GEMINI.value,
                "name": "Google Gemini",
                "display_name": "Google Gemini",
                "model": self.gemini_model,
                "available": bool(self.gemini_api_key),
                "reason": "" if self.gemini_api_key else "Gemini API key not configured",
            },
        }

    def get_default_provider(self) -> str:
        """Pick the configured provider when available, otherwise fall back safely."""
        statuses = self.get_provider_status()
        if statuses.get(self.default_provider, {}).get("available"):
            return self.default_provider
        return AIProvider.OLLAMA.value

    def get_available_providers(self) -> List[Dict[str, Any]]:
        """Return list of available AI providers based on configured API keys"""
        statuses = self.get_provider_status()
        icon_map = {
            AIProvider.OLLAMA.value: "ph-cube",
            AIProvider.OLLAMA_CLOUD.value: "ph-cloud",
            AIProvider.OPENAI.value: "ph-brain",
            AIProvider.GEMINI.value: "ph-sparkle",
        }
        providers = []
        for provider_id in (
            AIProvider.OLLAMA.value,
            AIProvider.OLLAMA_CLOUD.value,
            AIProvider.OPENAI.value,
            AIProvider.GEMINI.value,
        ):
            status = dict(statuses[provider_id])
            status["icon"] = icon_map[provider_id]
            status["default"] = provider_id == self.get_default_provider()
            providers.append(status)
        return providers

    async def generate_report_package(self, data: dict) -> Dict[str, Any]:
        """Generate the stored report payload, including RAG enrichment."""
        prompt_summary = self._build_report_evidence(data)
        rag_context = self.rag_service.build_analysis(data, prompt_summary)
        fallback_general, fallback_technical = self._build_fallback_reports(data, rag_context)

        prompt = f"""You are a senior cybersecurity analyst reviewing a scanned web address.
Your job is to decide how trustworthy the address looks using the provided scan evidence and the retrieved threat-knowledge snippets.
Focus on address legitimacy, redirect behavior, reputation, infrastructure, certificate health, and credential-collection clues.

Rules:
- Ground every claim in the provided scan evidence. Never invent detections, brands, CVEs, or hosting details.
- Use retrieved threat knowledge only as supporting context. If the knowledge match is weak or tentative, say so.
- Missing data is not proof. If evidence is unavailable, say "not observed" or "not available".
- Do not label a site as phishing unless the evidence clearly supports credential theft, impersonation, or deceptive collection behavior.
- If signals conflict, explain the uncertainty instead of overstating the risk.
- The UI renders plain text, so keep the writing crisp and readable with short paragraphs and bullet lines inside the strings.

Return ONLY valid JSON with exactly these keys:
{{
  "general": "...",
  "technical": "..."
}}

Write:
1. "general": 110-170 words for a non-technical user. Start with a one-sentence decision, explain the 2-4 strongest reasons behind that decision, then state whether opening or sharing the address is advisable and what the safest next action is.
2. "technical": 170-280 words. Use this exact internal structure inside the string:
Technical assessment for <url>:
- Address analysis: ...
- Reputation and scan evidence: ...
- Threat knowledge and MITRE context: ...
- Infrastructure and certificate: ...
- Page and DOM behavior: ...
- Recommended actions: ...

Use concrete values when present, especially risk score, top weighted sources, domain age, redirect count or host changes, VirusTotal counts, URLScan verdict, missing headers, password inputs, external scripts, CVEs, SSL issues, detected threat family, and MITRE ATT&CK mapping.

EVIDENCE:
{json.dumps(prompt_summary, ensure_ascii=False)}

RETRIEVED THREAT KNOWLEDGE:
{json.dumps(rag_context.get("prompt_context", {}), ensure_ascii=False)}
"""

        raw_response = await self._send_prompt(
            prompt,
            self.get_default_provider(),
            system_message=(
                "You are a precise cybersecurity analyst. Return only valid JSON with the requested keys. "
                "Be evidence-driven, conservative with claims, and especially careful when judging whether a URL or address is trustworthy."
            ),
            generation_options={
                "num_predict": 900,
                "temperature": 0.1,
                "top_p": 0.85,
            },
        )
        parsed = self._extract_report_payload(raw_response)

        if not parsed:
            return {
                "general": fallback_general,
                "technical": fallback_technical,
                "rag": rag_context,
            }

        general = (parsed.get("general") or "").strip()
        technical = (parsed.get("technical") or "").strip()

        return {
            "general": general or fallback_general,
            "technical": technical or fallback_technical,
            "rag": rag_context,
        }

    async def generate_dual_reports(self, data: dict) -> Tuple[str, str]:
        """Generate user-friendly and technical reports with safe fallback behavior."""
        report_package = await self.generate_report_package(data)
        return (
            str(report_package.get("general") or ""),
            str(report_package.get("technical") or ""),
        )

    async def generate_report(self, data: dict) -> str:
        """Generate AI security analysis report"""
        geo = data.get('details', {}).get('GeoIP', {})
        loc = f"{geo.get('country', 'Unknown')} ({geo.get('isp', 'Unknown')})"
        vt = data.get('details', {}).get('VirusTotal', {}).get('malicious_count', 0)
        meta = data.get('page_meta', {})
        
        prompt = f"""
        ACT AS A SENIOR SOC ANALYST.
        
        TARGET: {data.get('target_url', 'Unknown')}
        VERDICT: {data.get('verdict', 'Unknown')} (Risk Score: {data.get('risk_score', 0)}%)
        
        TECHNICAL INTEL:
        - Hosting: {loc}
        - SSL Status: {data.get('details', {}).get('SSLCheck', {}).get('status', 'N/A')}
        - Server: {data.get('server_info', {}).get('server', 'Unknown')}
        - Page Title: "{meta.get('title', 'N/A')}"
        - Redirects: {len(data.get('redirect_chain', []))} hops
        
        THREAT INDICATORS:
        - VirusTotal Detections: {vt}
        - Open Ports (Shodan): {len(data.get('details', {}).get('Shodan', {}).get('ports', []))}
        
        INSTRUCTIONS:
        1. Write a professional executive summary (approx 100 words).
        2. Analyze the legitimacy of the infrastructure based on the Hosting/Server info.
        3. If there are redirects, comment on whether they look suspicious.
        """
        return await self._send_prompt(prompt, self.default_provider)

    async def chat_about_scan(
        self,
        scan_data: dict,
        user_question: str,
        provider: Optional[str] = None,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Chat about scan with specified AI provider"""
        if provider is None:
            provider = self.get_default_provider()
        else:
            provider = self.normalize_provider(provider)
        
        # Extract key information from scan data
        url = scan_data.get('url', 'Unknown')
        verdict = scan_data.get('verdict', 'Unknown')
        risk_score = scan_data.get('risk_score', 0)
        
        details = scan_data.get('details', {})
        headers = scan_data.get('headers', {})
        server = scan_data.get('server', {})
        security_headers = scan_data.get('security_headers', {})
        dom_stats = scan_data.get('dom_stats', {})
        
        # Build structured context
        context_lines = [
            f"URL: {url}",
            f"Verdict: {verdict} (Risk: {risk_score}%)"
        ]
        
        # Server info
        if server and isinstance(server, dict):
            srv = server.get('server', '')
            if srv:
                context_lines.append(f"🖥️ Server: {srv}")
            powered_by = server.get('powered_by', '') or server.get('x-powered-by', '')
            if powered_by:
                context_lines.append(f"Powered by: {powered_by}")
        
        # Security headers status
        if security_headers and isinstance(security_headers, dict):
            present = [k for k, v in security_headers.items() if v and v != 'Missing']
            missing = [k for k, v in security_headers.items() if not v or v == 'Missing']
            if present:
                context_lines.append(f"Security headers present: {', '.join(present[:4])}")
            if missing:
                context_lines.append(f"Missing headers: {', '.join(missing[:4])}")
        
        # VirusTotal and threat info
        if details and isinstance(details, dict):
            vt = details.get('VirusTotal', {})
            if isinstance(vt, dict) and vt.get('malicious_count', 0) > 0:
                context_lines.append(f"VirusTotal malicious detections: {vt.get('malicious_count')}")
            
            geo = details.get('GeoIP', {})
            if isinstance(geo, dict):
                country = geo.get('country', '')
                isp = geo.get('isp', '')
                if country:
                    context_lines.append(f"Location: {country}" + (f" ({isp})" if isp else ""))
            
            ssl = details.get('SSLCheck', {})
            if isinstance(ssl, dict):
                ssl_status = ssl.get('status', '')
                if ssl_status:
                    context_lines.append(f"SSL: {ssl_status}")
        
        # DOM stats
        if dom_stats and isinstance(dom_stats, dict):
            scripts = dom_stats.get('total_scripts', dom_stats.get('scripts', 0))
            forms = dom_stats.get('total_forms', dom_stats.get('forms', 0))
            if scripts or forms:
                context_lines.append(f"Page profile: {scripts} scripts, {forms} forms")

        # WHOIS, TechStack, URLScan, CVEs
        if details and isinstance(details, dict):
            whois = details.get('WHOIS', {})
            if isinstance(whois, dict) and whois.get('domain_age_days'):
                context_lines.append(f"Domain age: {whois.get('domain_age_days')} days")

            tech = details.get('TechStack', {})
            if isinstance(tech, dict) and tech.get('technologies'):
                context_lines.append(f"Tech stack: {', '.join(tech.get('technologies', [])[:5])}")

            urlscan = details.get('URLScan', {})
            if isinstance(urlscan, dict) and urlscan.get('malicious'):
                context_lines.append("URLScan verdict: Malicious")

            cve_analysis = details.get('CVEAnalysis', {})
            if isinstance(cve_analysis, dict):
                vulns = cve_analysis.get('vulnerabilities', [])
                if vulns:
                    cve_ids = [v.get('id') for v in vulns[:3] if v.get('id')]
                    context_lines.append(f"Detected CVEs: {', '.join(cve_ids)}")

        recent_history = []
        for item in (history or [])[-6:]:
            role = (item.get("role") or "").strip().lower()
            content = (item.get("content") or "").strip()
            if role in {"user", "assistant"} and content:
                recent_history.append(f"{role.upper()}: {content}")
        
        context = "\n".join(context_lines)
        history_block = "\n".join(recent_history) if recent_history else "No prior conversation."
        
        prompt = f"""You are URL Analysis Using LLM, a practical cybersecurity analyst.
Answer like a calm security teammate who helps users make a decision quickly.
Use the scan evidence below, be clear about uncertainty, and keep the tone helpful rather than robotic.
Prefer this shape when it fits naturally:
- Direct answer first
- Why that answer fits the evidence
- What the user should do next

SCAN RESULTS:
{context}

RECENT CONVERSATION:
{history_block}

USER QUESTION: {user_question}

Give a direct, helpful answer based on the scan data.
Be specific and accurate.
If the evidence is incomplete, say so clearly.
Keep it under 220 words."""
        
        return await self._send_prompt(prompt, provider)

    async def _send_prompt(
        self,
        prompt: str,
        provider: str = "ollama",
        system_message: str = "You are a concise and accurate cybersecurity assistant.",
        generation_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send prompt to the specified AI provider"""
        provider = self.normalize_provider(provider)
        statuses = self.get_provider_status()
        provider_status = statuses.get(provider, {})
        if not provider_status.get("available"):
            reason = provider_status.get("reason", "Provider is unavailable")
            return f"{provider_status.get('display_name', provider)} unavailable: {reason}."

        if provider == "openai":
            return await self._send_openai(prompt)
        elif provider == "gemini":
            return await self._send_gemini(prompt)
        elif provider == "ollama_cloud":
            return await self._send_ollama_cloud(
                prompt,
                system_message=system_message,
                generation_options=generation_options,
            )
        else:
            return await self._send_ollama(
                prompt,
                system_message=system_message,
                generation_options=generation_options,
            )

    async def _send_ollama(
        self,
        prompt: str,
        system_message: str = "You are a concise and accurate cybersecurity assistant.",
        generation_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send prompt to local Ollama instance."""
        return await self._send_ollama_chat(
            api_url=self.ollama_api,
            model=self.ollama_model,
            prompt=prompt,
            system_message=system_message,
            generation_options=generation_options,
            provider_name="Ollama",
        )

    async def _send_ollama_cloud(
        self,
        prompt: str,
        system_message: str = "You are a concise and accurate cybersecurity assistant.",
        generation_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send prompt to Ollama Cloud via its remote API."""
        if not self.ollama_cloud_api_key:
            return "Ollama Cloud unavailable: API key not configured."

        return await self._send_ollama_chat(
            api_url=self.ollama_cloud_api,
            model=self.ollama_cloud_model,
            prompt=prompt,
            system_message=system_message,
            headers={"Authorization": f"Bearer {self.ollama_cloud_api_key}"},
            generation_options=generation_options,
            provider_name="Ollama Cloud",
        )

    async def _send_ollama_chat(
        self,
        *,
        api_url: str,
        model: str,
        prompt: str,
        system_message: str = "You are a concise and accurate cybersecurity assistant.",
        headers: Optional[Dict[str, str]] = None,
        generation_options: Optional[Dict[str, Any]] = None,
        provider_name: str = "Ollama",
    ) -> str:
        """Send a chat-style request to an Ollama-compatible API."""
        endpoint = self._normalize_ollama_chat_url(api_url)
        options = {
            "num_predict": 600,
            "temperature": 0.2,
            "top_p": 0.9,
        }
        if generation_options:
            options.update(generation_options)
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": system_message,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "stream": False,
            "keep_alive": "5m",
            "options": options,
        }
        
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    message = data.get("message", {}) if isinstance(data, dict) else {}
                    content = message.get("content") if isinstance(message, dict) else ""
                    if not content and isinstance(data, dict):
                        content = data.get("response", "")
                    return (content or "").strip() or "No response."
                error_text = self._extract_error_text(response)
                return f"{provider_name} Error (Status: {response.status_code}): {error_text}"
        except httpx.ConnectError:
            if provider_name == "Ollama Cloud":
                return "Ollama Cloud Error: unable to reach ollama.com right now."
            return "Ollama Error: local Ollama is not reachable. Start `ollama serve` and try again."
        except Exception as e:
            return f"{provider_name} Error: {str(e)}"

    async def _send_openai(self, prompt: str) -> str:
        """Send prompt to OpenAI via the Responses API."""
        if not self.openai_api_key:
            return "OpenAI GPT unavailable: API key not configured."
        
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.openai_model,
            "instructions": "You are a precise cybersecurity assistant analyzing URL Analysis Using LLM scan results.",
            "input": prompt,
            "max_output_tokens": 900,
            "reasoning": {"effort": "low"},
            "store": False,
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/responses",
                    headers=headers,
                    json=payload
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = self._extract_openai_response_text(data)
                    return content or "No response from OpenAI."
                elif response.status_code == 401:
                    return "OpenAI GPT unavailable: invalid API key."
                elif response.status_code == 429:
                    return f"OpenAI GPT temporary limit: {self._extract_error_text(response)}"
                elif response.status_code == 400:
                    return f"OpenAI GPT request error: {self._extract_error_text(response)}"
                else:
                    return f"OpenAI Error (Status: {response.status_code}): {self._extract_error_text(response)}"
        except Exception as e:
            return f"OpenAI Error: {str(e)}"

    async def _send_gemini(self, prompt: str) -> str:
        """Send prompt to Google Gemini API"""
        if not self.gemini_api_key:
            return "❌ Gemini API key not configured. Please add your API key in Settings or config.ini."
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={self.gemini_api_key}"
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.9,
                "maxOutputTokens": 900
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get('candidates', [])
                    if candidates:
                        parts = candidates[0].get('content', {}).get('parts', [])
                        if parts:
                            texts = [part.get("text", "") for part in parts if part.get("text")]
                            return "\n".join(texts).strip() or "No response from Gemini."
                    return "No response from Gemini."
                elif response.status_code == 400:
                    return f"❌ Gemini request failed: {self._extract_error_text(response)}"
                elif response.status_code == 429:
                    return "⚠️ Gemini rate limit exceeded. Please wait a moment and try again."
                else:
                    return f"Gemini Error (Status: {response.status_code}): {self._extract_error_text(response)}"
        except Exception as e:
            return f"Gemini Error: {str(e)}"

    def reload_config(self):
        """Reload configuration from config.ini"""
        self.__init__()

    def _normalize_ollama_chat_url(self, api_url: str) -> str:
        """Normalize Ollama-compatible endpoints to the chat API."""
        candidate = (api_url or "").strip() or "http://localhost:11434/api/chat"
        if candidate.endswith("/generate"):
            return candidate[:-len("/generate")] + "/chat"
        if candidate.endswith("/api"):
            return f"{candidate}/chat"
        if candidate.endswith("/api/"):
            return f"{candidate}chat"
        return candidate

    def _extract_openai_response_text(self, payload: Dict[str, Any]) -> str:
        """Extract text from a Responses API payload."""
        if not isinstance(payload, dict):
            return ""
        output_text = (payload.get("output_text") or "").strip()
        if output_text:
            return output_text

        chunks: List[str] = []
        for item in payload.get("output", []) or []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "message":
                for content in item.get("content", []) or []:
                    if not isinstance(content, dict):
                        continue
                    if content.get("type") == "output_text" and content.get("text"):
                        chunks.append(str(content["text"]))
                    elif content.get("type") == "refusal" and content.get("refusal"):
                        chunks.append(str(content["refusal"]))
        return "\n".join(part.strip() for part in chunks if part and part.strip()).strip()

    def _build_report_evidence(self, data: dict) -> Dict[str, Any]:
        """Build a compact but high-signal evidence package for report generation."""
        details = data.get("details", {}) or {}
        vt = details.get("VirusTotal", {}) if isinstance(details, dict) else {}
        abuse = details.get("AbuseIPDB", {}) if isinstance(details, dict) else {}
        shodan = details.get("Shodan", {}) if isinstance(details, dict) else {}
        deep = details.get("DeepContent", {}) if isinstance(details, dict) else {}
        geo = details.get("GeoIP", {}) if isinstance(details, dict) else {}
        ssl_info = details.get("SSLCheck", {}) if isinstance(details, dict) else {}
        whois = details.get("WHOIS", {}) if isinstance(details, dict) else {}
        tech = details.get("TechStack", {}) if isinstance(details, dict) else {}
        urlscan = details.get("URLScan", {}) if isinstance(details, dict) else {}
        cve_analysis = details.get("CVEAnalysis", {}) if isinstance(details, dict) else {}
        security_headers = data.get("security_headers", {}) or {}
        page_meta = data.get("page_meta", {}) or {}
        dom_stats = data.get("dom_stats", {}) or {}
        server_info = data.get("server_info", {}) or {}
        redirect_chain = data.get("redirect_chain", []) or []
        risk_breakdown = data.get("risk_breakdown", []) or []

        target_url = data.get("target_url", "Unknown")
        parsed_url = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        hostname = (parsed_url.hostname or "").lower()
        path = parsed_url.path or "/"
        path_depth = len([segment for segment in path.split("/") if segment])
        query_keys = re.findall(r"([a-zA-Z0-9_-]+)=", parsed_url.query or "")
        missing_headers = [key for key, value in security_headers.items() if value == "Missing"]
        present_headers = [key for key, value in security_headers.items() if value and value != "Missing"]

        redirect_summary = []
        redirect_hosts: List[str] = []
        for hop in redirect_chain[:6]:
            if not isinstance(hop, dict):
                continue
            hop_url = str(hop.get("url") or "")
            hop_host = (urlparse(hop_url if "://" in hop_url else f"https://{hop_url}").hostname or "").lower()
            if hop_host:
                redirect_hosts.append(hop_host)
            redirect_summary.append({
                "url": hop_url,
                "host": hop_host,
                "status": hop.get("status"),
                "server": hop.get("server", ""),
            })
        unique_redirect_hosts = list(dict.fromkeys(host for host in redirect_hosts if host))

        vulnerabilities = []
        for vuln in (cve_analysis.get("vulnerabilities", []) if isinstance(cve_analysis, dict) else [])[:6]:
            if not isinstance(vuln, dict):
                continue
            vulnerabilities.append({
                "id": vuln.get("id"),
                "severity": vuln.get("severity", "Unknown"),
                "cvss": vuln.get("cvss"),
                "technology": vuln.get("technology"),
            })

        suspicious_terms = self._extract_address_terms(
            target_url=target_url,
            hostname=hostname,
            page_title=page_meta.get("title", ""),
            content_signals=deep.get("signals", []) if isinstance(deep, dict) else [],
        )

        return {
            "target": {
                "url": target_url,
                "hostname": hostname or "unknown",
                "scheme": parsed_url.scheme or "unknown",
                "path": path,
                "path_depth": path_depth,
                "query_parameter_keys": query_keys[:8],
                "uses_http": (parsed_url.scheme or "").lower() == "http",
                "host_is_ip_literal": bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname or "")),
                "host_uses_punycode": "xn--" in hostname,
                "hostname_label_count": len([label for label in hostname.split(".") if label]),
                "suspicious_terms": suspicious_terms[:8],
            },
            "classification": {
                "verdict": data.get("verdict", "Unknown"),
                "risk_score": data.get("risk_score", 0),
                "top_weighted_sources": [
                    {
                        "source": item.get("source"),
                        "base_risk": item.get("base_risk", 0),
                        "weighted_risk": item.get("weighted_risk", 0),
                    }
                    for item in risk_breakdown[:5]
                    if isinstance(item, dict)
                ],
            },
            "reputation": {
                "virustotal": {
                    "status": vt.get("status", ""),
                    "malicious_count": vt.get("malicious_count", 0),
                    "suspicious_count": vt.get("suspicious_count", 0),
                    "malicious_engines": vt.get("malicious_engines", [])[:6],
                },
                "abuseipdb": {
                    "status": abuse.get("status", ""),
                    "score": abuse.get("score", 0),
                    "usage_type": abuse.get("usageType", ""),
                    "isp": abuse.get("isp", ""),
                    "total_reports": abuse.get("totalReports", 0),
                },
                "urlscan": {
                    "status": urlscan.get("status", ""),
                    "malicious": urlscan.get("malicious", False),
                    "score": urlscan.get("score", 0),
                    "brands": urlscan.get("brands", [])[:5],
                    "categories": urlscan.get("categories", [])[:5],
                    "page_domain": urlscan.get("page_domain", ""),
                    "page_country": urlscan.get("page_country", ""),
                },
            },
            "domain_and_hosting": {
                "domain": whois.get("domain", ""),
                "registrar": whois.get("registrar", ""),
                "domain_age_days": whois.get("domain_age_days", "Unknown"),
                "creation_date": whois.get("creation_date"),
                "expiration_date": whois.get("expiration_date"),
                "whois_signals": whois.get("signals", [])[:5] if isinstance(whois, dict) else [],
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", ""),
                "isp": geo.get("isp", "Unknown"),
                "organization": geo.get("org", geo.get("organization", "")),
            },
            "infrastructure": {
                "server": server_info.get("server", "Unknown"),
                "powered_by": server_info.get("powered_by", ""),
                "content_type": server_info.get("content_type", ""),
                "open_ports": shodan.get("ports", [])[:10] if isinstance(shodan, dict) else [],
                "organization": shodan.get("org", ""),
                "technologies": tech.get("technologies", [])[:12] if isinstance(tech, dict) else [],
                "tech_categories": tech.get("categories", {}) if isinstance(tech, dict) else {},
                "vulnerabilities": vulnerabilities,
            },
            "certificate": {
                "status": ssl_info.get("status", ""),
                "valid": ssl_info.get("valid", False),
                "issuer": ssl_info.get("issuer", "Unknown"),
                "subject": ssl_info.get("subject", ""),
                "valid_from": ssl_info.get("valid_from"),
                "valid_until": ssl_info.get("valid_until"),
                "days_remaining": ssl_info.get("days_remaining"),
                "tls_version": ssl_info.get("tls_version", ""),
                "cipher_suite": ssl_info.get("cipher_suite", ""),
                "issues": ssl_info.get("issues", [])[:6] if isinstance(ssl_info, dict) else [],
            },
            "redirects": {
                "count": len(redirect_chain),
                "hosts": unique_redirect_hosts[:6],
                "cross_host_redirect": len(unique_redirect_hosts) > 1,
                "chain": redirect_summary,
            },
            "page_and_dom": {
                "title": page_meta.get("title", "Unknown"),
                "description": page_meta.get("description", ""),
                "generator": page_meta.get("generator", ""),
                "password_inputs": dom_stats.get("password_inputs", 0),
                "hidden_inputs": dom_stats.get("hidden_inputs", 0),
                "total_forms": dom_stats.get("total_forms", 0),
                "total_scripts": dom_stats.get("total_scripts", 0),
                "external_scripts": (dom_stats.get("external_scripts", []) or [])[:8],
                "external_script_count": len(dom_stats.get("external_scripts", []) or []),
                "external_link_count": dom_stats.get("external_link_count", 0),
                "iframes": dom_stats.get("iframes", 0),
                "content_signals": deep.get("signals", [])[:6] if isinstance(deep, dict) else [],
            },
            "security_headers": {
                "score": data.get("security_headers_score", 0),
                "present": present_headers[:7],
                "missing": missing_headers[:7],
            },
        }

    def _extract_address_terms(
        self,
        *,
        target_url: str,
        hostname: str,
        page_title: str,
        content_signals: List[Any],
    ) -> List[str]:
        """Extract suspicious terms from the URL, hostname, and page title."""
        keyword_map = {
            "login": "login",
            "signin": "signin",
            "verify": "verify",
            "account": "account",
            "secure": "secure",
            "update": "update",
            "payment": "payment",
            "invoice": "invoice",
            "bank": "bank",
            "wallet": "wallet",
            "auth": "auth",
            "reset": "reset",
        }
        search_text = " ".join(
            [
                str(target_url or ""),
                str(hostname or ""),
                str(page_title or ""),
                " ".join(str(signal) for signal in content_signals if signal),
            ]
        ).lower()

        findings = [label for token, label in keyword_map.items() if token in search_text]
        return list(dict.fromkeys(findings))

    def _extract_report_payload(self, raw_response: str) -> Optional[Dict[str, str]]:
        """Parse an LLM response into the expected dual-report JSON structure."""
        if not raw_response or self._looks_like_provider_error(raw_response):
            return None

        cleaned = raw_response.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.DOTALL).strip()

        candidates = [cleaned]

        json_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if json_match:
            candidates.append(json_match.group(0))

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue

            if isinstance(parsed, dict):
                nested = parsed.get("reports")
                if isinstance(nested, dict):
                    parsed = nested
                return {
                    "general": str(
                        parsed.get("general")
                        or parsed.get("executive")
                        or parsed.get("summary")
                        or ""
                    ),
                    "technical": str(
                        parsed.get("technical")
                        or parsed.get("details")
                        or parsed.get("analysis")
                        or ""
                    ),
                }

        return None

    def _looks_like_provider_error(self, response_text: str) -> bool:
        """Detect provider or connectivity errors so we can fall back cleanly."""
        lowered = response_text.lower()
        error_markers = (
            "error:",
            "ollama error",
            "ollama cloud error",
            "openai error",
            "gemini error",
            "not configured",
            "not running",
            "unavailable:",
            "rate limit",
            "invalid openai api key",
            "invalid gemini api key",
            "failed to fetch",
            "connection error",
        )
        return any(marker in lowered for marker in error_markers)

    def _build_fallback_reports(self, data: dict, rag_context: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        """Build deterministic reports when no external LLM is available."""
        details = data.get("details", {}) or {}
        risk_score = data.get("risk_score", 0)
        verdict = data.get("verdict", "Unknown")
        url = data.get("target_url", "Unknown")
        server_info = data.get("server_info", {}) or {}
        security_headers = data.get("security_headers", {}) or {}
        dom_stats = data.get("dom_stats", {}) or {}
        risk_breakdown = data.get("risk_breakdown", []) or []

        vt = details.get("VirusTotal", {}) if isinstance(details, dict) else {}
        abuse = details.get("AbuseIPDB", {}) if isinstance(details, dict) else {}
        deep = details.get("DeepContent", {}) if isinstance(details, dict) else {}

        malicious_hits = vt.get("malicious_count", 0)
        abuse_score = abuse.get("score", 0)
        missing_headers = [key for key, value in security_headers.items() if value == "Missing"]
        suspicious_signals = deep.get("signals", []) if isinstance(deep, dict) else []
        password_inputs = dom_stats.get("password_inputs", 0)
        redirects = len(data.get("redirect_chain", []) or [])
        rag_context = rag_context or {}
        threat_name = str(rag_context.get("threat_name") or "").strip()
        threat_category = str(rag_context.get("category") or "").strip()
        threat_confidence = rag_context.get("confidence", 0)
        mitre = rag_context.get("mitre", {}) if isinstance(rag_context.get("mitre"), dict) else {}
        recommendations = rag_context.get("recommended_actions", []) if isinstance(rag_context.get("recommended_actions"), list) else []

        general_parts = [
            f"{url} was classified as {verdict} with a risk score of {risk_score}/100.",
        ]
        if threat_name and threat_name.lower() != "unknown":
            general_parts.append(
                f"The bundled threat knowledge base most closely matched this scan to {threat_name} ({threat_category or 'unknown category'}) at about {threat_confidence}% confidence."
            )
        if malicious_hits:
            general_parts.append(f"VirusTotal reported {malicious_hits} malicious detections.")
        if abuse_score:
            general_parts.append(f"AbuseIPDB returned an abuse confidence score of {abuse_score}%.")
        if password_inputs:
            general_parts.append("The page includes password input fields, which raises phishing risk when combined with suspicious content.")
        if redirects:
            general_parts.append(f"The scan observed {redirects} redirect step(s), which should be reviewed for unexpected routing.")
        if missing_headers:
            general_parts.append(f"Important security headers are missing, including {', '.join(missing_headers[:3])}.")
        if suspicious_signals:
            general_parts.append(f"Content analysis flagged signals such as {', '.join(suspicious_signals[:2])}.")
        if recommendations:
            general_parts.append(f"Best next step: {recommendations[0]}")
        else:
            general_parts.append("Review the full report before trusting or distributing the URL.")

        top_risks = ", ".join(item.get("source", "Unknown") for item in risk_breakdown[:3]) or "no major weighted contributors"
        technical_lines = [
            f"Technical assessment for {url}:",
            f"- Verdict: {verdict}; weighted risk score: {risk_score}/100.",
            f"- Top contributing sources: {top_risks}.",
            (
                f"- Threat knowledge and MITRE context: {threat_name or 'Unknown'}"
                f"{f' in {threat_category}' if threat_category else ''}; "
                f"confidence {threat_confidence}%; "
                f"MITRE {mitre.get('id', 'Unknown')} - {mitre.get('name', 'Unknown')} ({mitre.get('tactic', 'Unknown')})."
            ),
            f"- Server fingerprint: {server_info.get('server', 'Hidden')} {server_info.get('powered_by', '')}".strip(),
            f"- DOM profile: {dom_stats.get('total_scripts', 0)} scripts, {dom_stats.get('total_forms', 0)} forms, {password_inputs} password fields, {dom_stats.get('iframes', 0)} iframes.",
            f"- Security headers missing: {', '.join(missing_headers[:5]) if missing_headers else 'none observed in the tracked set'}.",
        ]
        if malicious_hits:
            technical_lines.append(f"- VirusTotal detections: {malicious_hits} malicious, {vt.get('suspicious_count', 0)} suspicious.")
        if abuse_score:
            technical_lines.append(f"- AbuseIPDB score: {abuse_score}% with {abuse.get('totalReports', 0)} report(s).")
        if suspicious_signals:
            technical_lines.append(f"- Deep content signals: {', '.join(suspicious_signals[:5])}.")
        technical_lines.append(
            "- Recommended actions: "
            + (" ".join(str(item) for item in recommendations[:3]) if recommendations else "validate redirects, verify hosting legitimacy, inspect page forms and scripts, and block or sandbox the URL if the business context is unclear.")
        )

        general = " ".join(part for part in general_parts if part).strip()
        technical = "\n".join(line for line in technical_lines if line and not line.endswith(": ")).strip()
        return general, technical

    def _extract_error_text(self, response: httpx.Response) -> str:
        """Extract a readable error message from provider responses."""
        try:
            payload = response.json()
        except ValueError:
            return response.text.strip()[:500] or "Unknown error"

        if isinstance(payload, dict):
            if isinstance(payload.get("error"), dict):
                return str(payload["error"].get("message") or payload["error"])
            if payload.get("error"):
                return str(payload["error"])
            if payload.get("message"):
                return str(payload["message"])
        return json.dumps(payload, ensure_ascii=False)[:500]
