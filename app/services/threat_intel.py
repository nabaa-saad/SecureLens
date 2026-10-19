"""
SecureLens Enterprise - Threat Intelligence Engine v3.0
Rebuilt with improved architecture, rate limiting, caching, and better API consistency.
"""

import httpx
import socket
import ssl
import configparser
import os
import whois
import re
import asyncio
import base64
import hashlib
import dns.resolver
from abc import ABC, abstractmethod
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from functools import lru_cache
from contextlib import asynccontextmanager
import logging
from cachetools import TTLCache
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from aiolimiter import AsyncLimiter

from app.utils.domain_utils import get_base_domain as get_registrable_domain

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s'
)
logger = logging.getLogger("SecureLens.ThreatIntel")

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration Management - Enhanced with validation
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class APIConfig:
    """Centralized API configuration with validation"""
    virustotal_key: str = ""
    shodan_key: str = ""
    ipinfo_token: str = ""
    abuseipdb_key: str = ""
    urlscan_key: str = ""
    securitytrails_key: str = ""
    chaos_key: str = ""
    nvd_key: str = ""
    
    # Performance settings
    max_connections: int = 15
    request_timeout: float = 20.0
    nvd_rate_limit: float = 0.4
    max_cve_enrichment: int = 500
    max_subdomain_scan: int = 200
    max_subdomain_resolve: int = 500
    
    # Cache settings
    ip_cache_ttl: int = 300
    scan_cache_ttl: int = 3600
    
    @classmethod
    def from_config_file(cls, path: str) -> 'APIConfig':
        """Load configuration from INI file"""
        config = configparser.ConfigParser()
        if os.path.exists(path):
            config.read(path)
        
        return cls(
            virustotal_key=config.get('API_KEYS', 'VIRUSTOTAL_API_KEY', fallback='').strip(),
            shodan_key=config.get('API_KEYS', 'SHODAN_API_KEY', fallback='').strip(),
            ipinfo_token=config.get('API_KEYS', 'IPINFO_TOKEN', fallback='').strip(),
            abuseipdb_key=config.get('API_KEYS', 'ABUSEIPDB_API_KEY', fallback='').strip(),
            urlscan_key=config.get('API_KEYS', 'URLSCAN_API_KEY', fallback='').strip(),
            securitytrails_key=config.get('API_KEYS', 'SECURITYTRAILS_API_KEY', fallback='').strip(),
            chaos_key=config.get('API_KEYS', 'CHAOS_API_KEY', fallback='').strip(),
            nvd_key=config.get('API_KEYS', 'NVD_API_KEY', fallback='').strip(),
            max_connections=config.getint('PERFORMANCE', 'MAX_CONNECTIONS', fallback=15),
            request_timeout=config.getfloat('PERFORMANCE', 'REQUEST_TIMEOUT', fallback=20.0),
            nvd_rate_limit=config.getfloat('PERFORMANCE', 'NVD_RATE_LIMIT_DELAY', fallback=0.4),
            max_cve_enrichment=config.getint('PERFORMANCE', 'MAX_CVE_ENRICHMENT', fallback=30),
            max_subdomain_scan=config.getint('PERFORMANCE', 'MAX_SUBDOMAIN_CVE_SCAN', fallback=50),
            max_subdomain_resolve=config.getint('PERFORMANCE', 'MAX_SUBDOMAIN_RESOLVE', fallback=100),
            ip_cache_ttl=config.getint('CACHE', 'IP_CACHE_TTL', fallback=300),
            scan_cache_ttl=config.getint('CACHE', 'SCAN_CACHE_TTL', fallback=3600),
        )

# Global config instance - locate config.ini at project root
from pathlib import Path
_project_root = Path(__file__).parent.parent.parent
config_path = str(_project_root / 'config.ini')
CONFIG = APIConfig.from_config_file(config_path)

def get_config(section: str, key: str) -> str:
    """Legacy helper for backwards compatibility"""
    config = configparser.ConfigParser()
    if os.path.exists(config_path):
        config.read(config_path)
    try:
        return config.get(section, key, fallback='').strip()
    except:
        return ""

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP Client Pool - Reusable connections with rate limiting
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPClientPool:
    """Managed HTTP client pool with connection reuse and rate limiting"""
    
    _instance: Optional['HTTPClientPool'] = None
    _clients: Dict[str, httpx.AsyncClient] = {}
    _limiters: Dict[str, AsyncLimiter] = {}
    
    # API-specific rate limits (requests per second)
    RATE_LIMITS = {
        "virustotal": 4,      # 4 req/sec
        "shodan": 1,          # 1 req/sec
        "urlscan": 2,         # 2 req/sec
        "abuseipdb": 5,       # 5 req/sec
        "nvd": 5,             # 5 req/sec with key
        "securitytrails": 2,  # 2 req/sec
        "chaos": 5,           # 5 req/sec
        "default": 10         # 10 req/sec default
    }
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def get_limiter(self, api_name: str) -> AsyncLimiter:
        """Get or create rate limiter for specific API"""
        if api_name not in self._limiters:
            rate = self.RATE_LIMITS.get(api_name, self.RATE_LIMITS["default"])
            self._limiters[api_name] = AsyncLimiter(rate, 1)
        return self._limiters[api_name]
    
    async def get_client(self, api_name: str = "default") -> httpx.AsyncClient:
        """Get or create HTTP client for specific API"""
        if api_name not in self._clients:
            self._clients[api_name] = httpx.AsyncClient(
                timeout=httpx.Timeout(CONFIG.request_timeout),
                limits=httpx.Limits(
                    max_connections=CONFIG.max_connections,
                    max_keepalive_connections=5
                ),
                follow_redirects=True,
                verify=False,
                http2=True
            )
        return self._clients[api_name]
    
    async def close_all(self):
        """Close all HTTP clients"""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

# Global HTTP pool
http_pool = HTTPClientPool()

# ═══════════════════════════════════════════════════════════════════════════════
# Caching Layer - Thread-safe with TTL
# ═══════════════════════════════════════════════════════════════════════════════

class CacheManager:
    """Centralized cache management with TTL support"""
    
    def __init__(self):
        self.ip_cache = TTLCache(maxsize=1000, ttl=CONFIG.ip_cache_ttl)
        self.domain_cache = TTLCache(maxsize=500, ttl=3600)
        self.dns_cache = TTLCache(maxsize=500, ttl=300)
        self.subdomain_cache = TTLCache(maxsize=200, ttl=1800)
    
    def get_ip(self, hostname: str) -> Optional[str]:
        return self.ip_cache.get(hostname)
    
    def set_ip(self, hostname: str, ip: str):
        self.ip_cache[hostname] = ip
    
    def get_domain(self, hostname: str) -> Optional[str]:
        return self.domain_cache.get(hostname)
    
    def set_domain(self, hostname: str, domain: str):
        self.domain_cache[hostname] = domain
    
    def clear_all(self):
        self.ip_cache.clear()
        self.domain_cache.clear()
        self.dns_cache.clear()
        self.subdomain_cache.clear()

# Global cache
cache = CacheManager()


async def gather_in_batches(coroutines: List[Any], batch_size: int, return_exceptions: bool = True) -> List[Any]:
    """Run coroutine work in bounded batches to avoid bursty fan-out."""
    if not coroutines:
        return []

    results: List[Any] = []
    normalized_batch_size = max(1, int(batch_size or 1))

    for start in range(0, len(coroutines), normalized_batch_size):
        current_batch = coroutines[start:start + normalized_batch_size]
        batch_results = await asyncio.gather(*current_batch, return_exceptions=return_exceptions)
        results.extend(batch_results)

    return results

# ═══════════════════════════════════════════════════════════════════════════════
# Network Utilities - Enhanced with caching and retries
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkUtils:
    """Network utility functions with caching and error handling"""
    
    @staticmethod
    def get_hostname(url: str) -> Optional[str]:
        """Extract hostname from URL"""
        try:
            if not url:
                return None
            parsed = urlparse(url if '://' in url else f'http://{url}')
            hostname = parsed.netloc or parsed.path.split('/')[0]
            return hostname.lower().strip() if hostname else None
        except:
            return None
    
    @staticmethod
    def get_base_domain(hostname: str) -> str:
        """Extract base domain from hostname"""
        if not hostname:
            return ""

        cached = cache.get_domain(hostname)
        if cached:
            return cached

        base = get_registrable_domain(hostname)
        cache.set_domain(hostname, base)
        return base

    @staticmethod
    async def resolve_ip(hostname: str) -> Optional[str]:
        """Resolve hostname to IP with caching"""
        if not hostname:
            return None
        
        cached = cache.get_ip(hostname)
        if cached:
            return cached
        
        try:
            ip = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyname, hostname),
                timeout=5.0
            )
            cache.set_ip(hostname, ip)
            return ip
        except Exception as e:
            logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return None
    
    @staticmethod
    async def get_ip_from_url(url: str) -> Optional[str]:
        """Resolve IP from URL"""
        hostname = NetworkUtils.get_hostname(url)
        return await NetworkUtils.resolve_ip(hostname) if hostname else None
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except:
            return False
    
    @staticmethod
    def clear_cache():
        """Clear all network caches"""
        cache.clear_all()

# ═══════════════════════════════════════════════════════════════════════════════
# Base Scanner Strategy - Enhanced with better error handling
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    """Standardized scan result structure"""
    source: str
    status: str
    risk_contribution: int = 0
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        result = {
            "source": self.source,
            "status": self.status,
            "risk_contribution": self.risk_contribution
        }
        result.update(self.data)
        if self.error:
            result["error"] = self.error
        return result

class AsyncScannerStrategy(ABC):
    """Base class for all security scanners"""
    
    name: str = "BaseScanner"
    requires_api_key: bool = True
    
    @abstractmethod
    async def scan(self, target: str) -> dict:
        """Execute scan and return results"""
        pass
    
    def _success(self, data: dict, risk: int = 0) -> dict:
        """Generate success response"""
        return {"source": self.name, "status": "Found", "risk_contribution": min(risk, 100), **data}
    
    def _error(self, message: str, partial_data: dict = None) -> dict:
        """Generate error response"""
        result = {"source": self.name, "status": "Error", "error": message, "risk_contribution": 0}
        if partial_data:
            result.update(partial_data)
        return result
    
    def _no_key(self, partial_data: dict = None) -> dict:
        """Response when API key is missing"""
        result = {"source": self.name, "status": "No API Key", "risk_contribution": 0}
        if partial_data:
            result.update(partial_data)
        return result

# ═══════════════════════════════════════════════════════════════════════════════
# Content Scanner - Deep page analysis
# ═══════════════════════════════════════════════════════════════════════════════

class DeepContentScanner(AsyncScannerStrategy):
    """Deep content analysis - redirects, headers, DOM, metadata, security"""
    
    name = "DeepContent"
    requires_api_key = False
    
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    SUSPICIOUS_PATTERNS = [
        (r'password|passwd|login|signin', 'Login form detected'),
        (r'credit.?card|cvv|expir', 'Payment information requested'),
        (r'bank|paypal|venmo|zelle', 'Financial service reference'),
        (r'verify.?account|confirm.?identity', 'Account verification language'),
        (r'urgent|immediately|suspended', 'Urgency language detected'),
    ]
    
    async def scan(self, url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            client = await http_pool.get_client("content")
            response = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
            })
            
            # Build redirect chain
            chain = []
            for hist in response.history:
                chain.append({
                    "url": str(hist.url),
                    "status": hist.status_code,
                    "server": hist.headers.get("Server", "Unknown")
                })
            chain.append({
                "url": str(response.url),
                "status": response.status_code,
                "server": response.headers.get("Server", "Unknown")
            })
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            page_text = soup.get_text().lower()
            
            # Page metadata
            meta_tags = {
                "title": soup.title.string.strip() if soup.title and soup.title.string else "No Title",
                "description": "",
                "keywords": "",
                "generator": "",
                "author": "",
                "robots": ""
            }
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                if name in meta_tags:
                    meta_tags[name] = content[:200]
            
            # DOM Analysis
            scripts = soup.find_all('script', src=True)
            forms = soup.find_all('form')
            inputs = soup.find_all('input')
            links = soup.find_all('a', href=True)
            iframes = soup.find_all('iframe')
            
            external_scripts = [s['src'] for s in scripts if s['src'].startswith('http')][:10]
            external_links = [a['href'] for a in links if a['href'].startswith('http')]
            
            dom_stats = {
                "total_scripts": len(scripts),
                "external_scripts": external_scripts,
                "inline_scripts": len(soup.find_all('script', src=False)),
                "total_forms": len(forms),
                "password_inputs": len([i for i in inputs if i.get('type') == 'password']),
                "hidden_inputs": len([i for i in inputs if i.get('type') == 'hidden']),
                "total_links": len(links),
                "external_link_count": len(external_links),
                "iframes": len(iframes)
            }
            
            # Server Info
            server_info = {
                "server": response.headers.get("Server", "Hidden"),
                "powered_by": response.headers.get("X-Powered-By", ""),
                "content_type": response.headers.get("Content-Type", ""),
                "cache_control": response.headers.get("Cache-Control", "")
            }
            
            # Security Headers Analysis
            security_headers = {}
            headers_present = 0
            for header in self.SECURITY_HEADERS:
                value = response.headers.get(header)
                security_headers[header] = value or "Missing"
                if value:
                    headers_present += 1
            
            security_score = int((headers_present / len(self.SECURITY_HEADERS)) * 100)
            
            # Risk Calculation with detailed signals
            risk = 0
            signals = []
            
            # Check for suspicious patterns
            for pattern, description in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, page_text):
                    # Only add risk if it's suspicious context
                    if dom_stats['password_inputs'] > 0:
                        risk += 10
                        signals.append(description)
            
            # HTTP password form
            if dom_stats['password_inputs'] > 0 and url.startswith("http://"):
                risk += 40
                signals.append("Password form over insecure HTTP")
            
            # Excessive redirects
            if len(chain) > 3:
                risk += 15
                signals.append(f"Redirect chain ({len(chain)} hops)")
            
            # Multiple iframes
            if dom_stats['iframes'] > 3:
                risk += 10
                signals.append(f"Multiple iframes ({dom_stats['iframes']})")
            
            # Poor security headers
            if security_score < 30:
                risk += 15
                signals.append(f"Weak security headers ({security_score}%)")
            
            # Many hidden inputs
            if dom_stats['hidden_inputs'] > 5:
                risk += 10
                signals.append(f"Hidden inputs ({dom_stats['hidden_inputs']})")
            
            # External script heavy
            if len(external_scripts) > 10:
                risk += 5
                signals.append(f"Many external scripts ({len(external_scripts)})")
            
            return {
                "source": "DeepContent",
                "status": "Success",
                "final_url": str(response.url),
                "redirect_chain": chain,
                "redirect_count": len(chain),
                "http_headers": dict(response.headers),
                "page_meta": meta_tags,
                "dom_stats": dom_stats,
                "server_info": server_info,
                "security_headers": security_headers,
                "security_headers_score": security_score,
                "signals": signals,
                "risk_contribution": min(risk, 100)
            }
            
        except httpx.TimeoutException:
            return self._error("Request timed out", {
                "redirect_chain": [], "http_headers": {}, "page_meta": {"title": "Timeout"},
                "dom_stats": {}, "server_info": {}, "security_headers": {}, "security_headers_score": 0
            })
        except Exception as e:
            logger.error(f"DeepContent scan error: {e}")
            return self._error(str(e), {
                "redirect_chain": [], "http_headers": {}, "page_meta": {"title": "Error"},
                "dom_stats": {}, "server_info": {}, "security_headers": {}, "security_headers_score": 0
            })

# ═══════════════════════════════════════════════════════════════════════════════
# VirusTotal Scanner - Enhanced with rate limiting
# ═══════════════════════════════════════════════════════════════════════════════

class VirusTotalScanner(AsyncScannerStrategy):
    """VirusTotal URL and domain reputation analysis"""
    
    name = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def scan(self, url: str) -> dict:
        if not self.api_key:
            return self._no_key()
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            limiter = http_pool.get_limiter("virustotal")
            async with limiter:
                client = await http_pool.get_client("virustotal")
                headers = {"x-apikey": self.api_key}
                
                # Create URL ID
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                
                # Try URL analysis first
                response = await client.get(f"{self.BASE_URL}/urls/{url_id}", headers=headers)
                
                # Fall back to domain if URL not found
                if response.status_code == 404:
                    hostname = NetworkUtils.get_hostname(url)
                    if hostname:
                        response = await client.get(f"{self.BASE_URL}/domains/{hostname}", headers=headers)
                
                if response.status_code == 200:
                    data = response.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    harmless = stats.get('harmless', 0)
                    undetected = stats.get('undetected', 0)
                    total = malicious + suspicious + harmless + undetected
                    
                    # Get malicious engine details
                    malicious_engines = []
                    for engine, result in data.get('last_analysis_results', {}).items():
                        if result.get('category') == 'malicious':
                            malicious_engines.append({
                                "name": engine,
                                "result": result.get('result', 'Malicious')
                            })
                    
                    # Risk calculation
                    risk = 0
                    if malicious >= 5:
                        risk = 100
                    elif malicious >= 3:
                        risk = 80
                    elif malicious >= 1:
                        risk = 50 + (malicious * 10)
                    elif suspicious > 0:
                        risk = 20 + (suspicious * 5)
                    
                    status = "Clean"
                    if malicious > 0:
                        status = f"Malicious ({malicious} detections)"
                    elif suspicious > 0:
                        status = f"Suspicious ({suspicious} flags)"
                    
                    return self._success({
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": harmless,
                        "undetected_count": undetected,
                        "total_engines": total,
                        "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
                        "malicious_engines": malicious_engines[:15],
                        "reputation": data.get('reputation', 0),
                        "categories": data.get('categories', {}),
                        "last_analysis_date": datetime.utcfromtimestamp(
                            data.get('last_analysis_date', 0)
                        ).strftime('%Y-%m-%d %H:%M') if data.get('last_analysis_date') else None,
                    }, risk)
                
                return {"source": "VirusTotal", "status": "Not Found", "risk_contribution": 0}
                
        except httpx.TimeoutException:
            return self._error("Timeout")
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return self._error(str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# AbuseIPDB Scanner - IP reputation
# ═══════════════════════════════════════════════════════════════════════════════

class AbuseIPDBScanner(AsyncScannerStrategy):
    """AbuseIPDB IP reputation analysis"""
    
    name = "AbuseIPDB"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def scan(self, url: str) -> dict:
        ip = await NetworkUtils.get_ip_from_url(url)
        if not ip:
            return {"source": "AbuseIPDB", "status": "No IP", "risk_contribution": 0}
        
        if not self.api_key:
            return self._no_key()
        
        try:
            limiter = http_pool.get_limiter("abuseipdb")
            async with limiter:
                client = await http_pool.get_client("abuseipdb")
                headers = {'Key': self.api_key, 'Accept': 'application/json'}
                params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''}
                
                response = await client.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    score = data.get('abuseConfidenceScore', 0)
                    
                    return self._success({
                        "ip": ip,
                        "score": score,
                        "usageType": data.get('usageType'),
                        "isp": data.get('isp'),
                        "domain": data.get('domain'),
                        "countryCode": data.get('countryCode'),
                        "totalReports": data.get('totalReports', 0),
                        "numDistinctUsers": data.get('numDistinctUsers', 0),
                        "lastReported": data.get('lastReportedAt'),
                        "isWhitelisted": data.get('isWhitelisted', False),
                        "isTor": data.get('isTor', False),
                    }, score)
                
                return self._error(f"HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
            return self._error(str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# URLScan Scanner - Live URL analysis with screenshots
# ═══════════════════════════════════════════════════════════════════════════════

class URLScanScanner(AsyncScannerStrategy):
    """URLScan.io URL analysis with screenshot capture"""
    
    name = "URLScan"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def scan(self, url: str) -> dict:
        if not self.api_key:
            return {"source": "URLScan", "status": "No API Key", "screenshot_url": None, "risk_contribution": 0}
        
        try:
            limiter = http_pool.get_limiter("urlscan")
            async with limiter:
                client = await http_pool.get_client("urlscan")
                headers = {'API-Key': self.api_key}
                
                # Search for existing scans first
                search_response = await client.get(
                    'https://urlscan.io/api/v1/search/',
                    headers=headers,
                    params={'q': f'page.url:"{url}"', 'size': 1}
                )
                
                if search_response.status_code == 200:
                    results = search_response.json().get('results', [])
                    
                    if results:
                        res = results[0]
                        task = res.get('task', {})
                        verdict = res.get('verdicts', {}).get('overall', {})
                        page = res.get('page', {})
                        task_uuid = task.get('uuid', '')
                        
                        return self._success({
                            "uuid": task_uuid,
                            "report_url": f"https://urlscan.io/result/{task_uuid}/" if task_uuid else None,
                            "screenshot_url": f"https://urlscan.io/screenshots/{task_uuid}.png" if task_uuid else None,
                            "malicious": verdict.get('malicious', False),
                            "score": verdict.get('score', 0),
                            "brands": verdict.get('brands', []),
                            "categories": verdict.get('categories', []),
                            "task_time": task.get('time', ''),
                            "page_url": page.get('url', ''),
                            "page_domain": page.get('domain', ''),
                            "page_ip": page.get('ip', ''),
                            "page_country": page.get('country', ''),
                            "page_server": page.get('server', ''),
                        }, 80 if verdict.get('malicious') else 0)
                
                # Submit new scan
                submit_response = await client.post(
                    'https://urlscan.io/api/v1/scan/',
                    headers={**headers, 'Content-Type': 'application/json'},
                    json={"url": url, "visibility": "unlisted"}
                )
                
                if submit_response.status_code == 200:
                    task_uuid = submit_response.json().get('uuid', '')

                    # Poll progressively so URLScan can return as soon as it is
                    # ready instead of always blocking the reputation stage for a
                    # fixed delay.
                    for delay_seconds in (2, 2, 3, 5):
                        await asyncio.sleep(delay_seconds)
                        result_response = await client.get(
                            f"https://urlscan.io/api/v1/result/{task_uuid}/",
                            headers=headers
                        )

                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            verdict = result_data.get('verdicts', {}).get('overall', {})
                            task = result_data.get('task', {})
                            page = result_data.get('page', {})

                            return self._success({
                                "uuid": task_uuid,
                                "report_url": f"https://urlscan.io/result/{task_uuid}/",
                                "screenshot_url": f"https://urlscan.io/screenshots/{task_uuid}.png",
                                "malicious": verdict.get('malicious', False),
                                "score": verdict.get('score', 0),
                                "brands": verdict.get('brands', []),
                                "categories": verdict.get('categories', []),
                                "task_time": task.get('time', ''),
                                "page_url": page.get('url', ''),
                                "page_domain": page.get('domain', ''),
                                "page_ip": page.get('ip', ''),
                                "page_country": page.get('country', ''),
                            }, 80 if verdict.get('malicious') else 0)

                        if result_response.status_code not in (400, 404):
                            logger.debug(
                                "URLScan result lookup for %s returned status %s",
                                task_uuid,
                                result_response.status_code,
                            )
                            break

                    return {
                        "source": "URLScan",
                        "status": "Pending",
                        "uuid": task_uuid,
                        "report_url": f"https://urlscan.io/result/{task_uuid}/",
                        "screenshot_url": f"https://urlscan.io/screenshots/{task_uuid}.png",
                        "risk_contribution": 0
                    }
                
                return {"source": "URLScan", "status": "Submit Failed", "screenshot_url": None, "risk_contribution": 0}
                
        except Exception as e:
            logger.error(f"URLScan error: {e}")
            return self._error(str(e), {"screenshot_url": None})

# ═══════════════════════════════════════════════════════════════════════════════
# Shodan Scanner - Infrastructure intelligence
# ═══════════════════════════════════════════════════════════════════════════════

class ShodanScanner(AsyncScannerStrategy):
    """Shodan infrastructure intelligence with service detection"""
    
    name = "Shodan"
    RISKY_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def scan(self, url: str) -> dict:
        ip = await NetworkUtils.get_ip_from_url(url)
        if not ip:
            return {"source": "Shodan", "status": "Could not resolve IP", "risk_contribution": 0}
        
        if not self.api_key:
            return {"source": "Shodan", "status": "No API Key", "ip": ip, "risk_contribution": 0}
        
        try:
            limiter = http_pool.get_limiter("shodan")
            async with limiter:
                client = await http_pool.get_client("shodan")
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": self.api_key}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    ports = data.get('ports', [])
                    vulns = list(data.get('vulns', []))
                    
                    # Extract service details
                    services = []
                    for item in data.get('data', [])[:15]:
                        services.append({
                            "port": item.get('port'),
                            "transport": item.get('transport', 'tcp'),
                            "product": item.get('product', 'Unknown'),
                            "version": item.get('version', ''),
                            "module": item.get('_shodan', {}).get('module', ''),
                            "banner": (item.get('data', '') or '')[:200]
                        })
                    
                    # Risk calculation
                    risk = 0
                    if vulns:
                        risk += min(len(vulns) * 8, 50)
                    
                    exposed_risky = [p for p in ports if p in self.RISKY_PORTS]
                    if exposed_risky:
                        risk += min(len(exposed_risky) * 5, 25)
                    
                    if len(ports) > 20:
                        risk += 10
                    
                    return self._success({
                        "ip": ip,
                        "hostnames": data.get('hostnames', []),
                        "org": data.get('org', 'Unknown'),
                        "isp": data.get('isp', 'Unknown'),
                        "asn": data.get('asn', ''),
                        "country": data.get('country_name', 'Unknown'),
                        "city": data.get('city', 'Unknown'),
                        "os": data.get('os') or 'Unknown',
                        "ports": sorted(ports),
                        "port_count": len(ports),
                        "services": services,
                        "vulns": vulns,
                        "vulns_count": len(vulns),
                        "exposed_risky_ports": exposed_risky,
                        "last_update": data.get('last_update', ''),
                    }, min(risk, 85))
                
                elif response.status_code == 404:
                    return {"source": "Shodan", "status": "Not Indexed", "ip": ip, "risk_contribution": 0}
                else:
                    return self._error(f"HTTP {response.status_code}", {"ip": ip})
                    
        except Exception as e:
            logger.error(f"Shodan error: {e}")
            return self._error(str(e), {"ip": ip})

# ═══════════════════════════════════════════════════════════════════════════════
# GeoIP Scanner - IP geolocation
# ═══════════════════════════════════════════════════════════════════════════════

class GeoScanner(AsyncScannerStrategy):
    """IP geolocation with multiple fallback providers"""
    
    name = "GeoIP"
    requires_api_key = False
    
    def __init__(self, token: str = ""):
        self.token = token
    
    async def scan(self, url: str) -> dict:
        ip = await NetworkUtils.get_ip_from_url(url)
        if not ip:
            return {"source": "GeoIP", "status": "No IP", "country": "Unknown", "city": "Unknown", "risk_contribution": 0}
        
        try:
            client = await http_pool.get_client("geo")
            
            # Try IPinfo first if token available
            if self.token:
                response = await client.get(f"https://ipinfo.io/{ip}?token={self.token}")
                if response.status_code == 200:
                    d = response.json()
                    return self._success({
                        "provider": "IPinfo",
                        "ip": ip,
                        "country": d.get('country', 'Unknown'),
                        "city": d.get('city', 'Unknown'),
                        "region": d.get('region', 'Unknown'),
                        "isp": d.get('org', 'Unknown'),
                        "loc": d.get('loc', ''),
                        "timezone": d.get('timezone', ''),
                    })
            
            # Fallback to free IP-API
            response = await client.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                d = response.json()
                if d.get('status') == 'success':
                    return self._success({
                        "provider": "IP-API",
                        "ip": ip,
                        "country": d.get('country', 'Unknown'),
                        "city": d.get('city', 'Unknown'),
                        "region": d.get('regionName', 'Unknown'),
                        "isp": d.get('isp', 'Unknown'),
                        "org": d.get('org', 'Unknown'),
                        "as": d.get('as', ''),
                    })
            
            return {"source": "GeoIP", "status": "Failed", "country": "Unknown", "risk_contribution": 0}
            
        except Exception as e:
            return self._error(str(e), {"country": "Unknown"})

# ═══════════════════════════════════════════════════════════════════════════════
# SSL Scanner - Certificate analysis
# ═══════════════════════════════════════════════════════════════════════════════

class SSLScanner(AsyncScannerStrategy):
    """SSL/TLS certificate analysis"""
    
    name = "SSLCheck"
    requires_api_key = False
    
    async def scan(self, url: str) -> dict:
        hostname = NetworkUtils.get_hostname(url)
        if not hostname:
            return {"source": "SSLCheck", "status": "No Hostname", "risk_contribution": 0}
        
        try:
            def check_ssl():
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return cert, cipher, version
            
            cert, cipher, version = await asyncio.wait_for(
                asyncio.to_thread(check_ssl),
                timeout=15.0
            )
            
            # Parse certificate
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            days_remaining = (not_after - datetime.now()).days
            
            # Get SANs
            san = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    san.append(ext[1])
            
            # Risk calculation
            risk = 0
            issues = []
            
            if days_remaining < 0:
                risk += 50
                issues.append("Certificate expired")
            elif days_remaining < 30:
                risk += 20
                issues.append(f"Expires in {days_remaining} days")
            
            if version in ['TLSv1', 'TLSv1.0', 'TLSv1.1']:
                risk += 25
                issues.append(f"Outdated TLS version: {version}")
            
            if 'Let\'s Encrypt' not in issuer.get('organizationName', '') and \
               issuer.get('commonName', '') == subject.get('commonName', ''):
                risk += 30
                issues.append("Self-signed certificate")
            
            return self._success({
                "valid": days_remaining >= 0,
                "subject": subject.get('commonName', ''),
                "issuer": issuer.get('organizationName', issuer.get('commonName', '')),
                "issuer_country": issuer.get('countryName', ''),
                "valid_from": not_before.strftime('%Y-%m-%d'),
                "valid_until": not_after.strftime('%Y-%m-%d'),
                "days_remaining": days_remaining,
                "san_domains": san[:10],
                "san_count": len(san),
                "tls_version": version,
                "cipher_suite": cipher[0] if cipher else 'Unknown',
                "key_bits": cipher[2] if cipher else 0,
                "issues": issues,
            }, risk)
            
        except ssl.SSLCertVerificationError as e:
            return {"source": "SSLCheck", "status": "Invalid Certificate", "error": str(e), "risk_contribution": 40}
        except socket.timeout:
            return {"source": "SSLCheck", "status": "Timeout", "risk_contribution": 5}
        except ConnectionRefusedError:
            return {"source": "SSLCheck", "status": "No SSL/TLS", "risk_contribution": 10}
        except Exception as e:
            return self._error(str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# DNS Scanner - DNS record analysis
# ═══════════════════════════════════════════════════════════════════════════════

class DNSScanner(AsyncScannerStrategy):
    """DNS record analysis"""
    
    name = "DNS"
    requires_api_key = False
    
    async def scan(self, url: str) -> dict:
        hostname = NetworkUtils.get_hostname(url)
        if not hostname:
            return {"source": "DNS", "status": "No Hostname", "risk_contribution": 0}
        
        try:
            records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            async def resolve_record(record_type):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    resolver.lifetime = 10
                    answers = await asyncio.to_thread(resolver.resolve, hostname, record_type)
                    return record_type, [str(r) for r in answers]
                except:
                    return record_type, []
            
            tasks = [resolve_record(rt) for rt in record_types]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, tuple):
                    record_type, values = result
                    if values:
                        records[record_type] = values
            
            # Check for SPF, DMARC, DKIM
            security_records = {
                "spf": False,
                "dmarc": False,
                "dkim": False
            }
            
            txt_records = records.get('TXT', [])
            for txt in txt_records:
                if 'v=spf1' in txt.lower():
                    security_records['spf'] = True
            
            # Check DMARC
            try:
                dmarc_answers = await asyncio.to_thread(
                    dns.resolver.resolve, f'_dmarc.{hostname}', 'TXT'
                )
                security_records['dmarc'] = True
            except:
                pass
            
            # Risk based on email security
            risk = 0
            base_domain = NetworkUtils.get_base_domain(hostname)
            if records.get('MX') and not security_records['spf']:
                risk += 10
            if records.get('MX') and not security_records['dmarc']:
                risk += 10
            
            return self._success({
                "hostname": hostname,
                "records": records,
                "a_records": records.get('A', []),
                "mx_records": records.get('MX', []),
                "ns_records": records.get('NS', []),
                "txt_records": txt_records[:5],
                "security_records": security_records,
                "has_ipv6": bool(records.get('AAAA')),
            }, risk)
            
        except Exception as e:
            logger.error(f"DNS scan error: {e}")
            return self._error(str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# WHOIS Scanner - Domain registration info
# ═══════════════════════════════════════════════════════════════════════════════

class WhoisScanner(AsyncScannerStrategy):
    """WHOIS domain registration analysis"""
    
    name = "WHOIS"
    requires_api_key = False
    
    async def scan(self, url: str) -> dict:
        hostname = NetworkUtils.get_hostname(url)
        if not hostname:
            return {"source": "WHOIS", "status": "No Hostname", "risk_contribution": 0}
        
        base_domain = NetworkUtils.get_base_domain(hostname)
        
        try:
            def get_whois():
                return whois.whois(base_domain)
            
            w = await asyncio.wait_for(asyncio.to_thread(get_whois), timeout=15.0)
            
            # Parse dates
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            # Calculate domain age
            domain_age_days = 0
            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
            
            # Risk calculation
            risk = 0
            signals = []
            
            if domain_age_days < 30:
                risk += 35
                signals.append("Domain less than 30 days old")
            elif domain_age_days < 90:
                risk += 20
                signals.append("Domain less than 90 days old")
            elif domain_age_days < 365:
                risk += 10
                signals.append("Domain less than 1 year old")
            
            # Privacy protection (not necessarily bad, but worth noting)
            registrar = str(w.registrar or '').lower()
            if 'privacy' in registrar or 'proxy' in registrar or 'protected' in registrar:
                signals.append("Privacy-protected registration")
            
            return self._success({
                "domain": base_domain,
                "registrar": w.registrar,
                "creation_date": creation_date.strftime('%Y-%m-%d') if creation_date else None,
                "expiration_date": expiration_date.strftime('%Y-%m-%d') if expiration_date else None,
                "updated_date": str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date)[:10] if w.updated_date else None,
                "domain_age_days": domain_age_days,
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "country": w.country,
                "state": w.state,
                "org": w.org,
                "signals": signals,
            }, risk)
            
        except Exception as e:
            logger.debug(f"WHOIS error for {base_domain}: {e}")
            return {"source": "WHOIS", "status": "Lookup Failed", "error": str(e), "risk_contribution": 5}

# ═══════════════════════════════════════════════════════════════════════════════
# Technology Stack Scanner - Tech detection
# ═══════════════════════════════════════════════════════════════════════════════

class TechStackScanner(AsyncScannerStrategy):
    """Technology stack detection"""
    
    name = "TechStack"
    requires_api_key = False
    
    SIGNATURES = {
        # CMS & Frameworks
        "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
        "Drupal": [r"drupal", r"/sites/default/"],
        "Joomla": [r"joomla", r"/components/com_"],
        "Shopify": [r"shopify", r"cdn.shopify.com"],
        "Wix": [r"wix.com", r"wixstatic.com"],
        
        # JavaScript Frameworks
        "React": [r"react", r"__react", r"react-dom"],
        "Vue.js": [r"vue\.js", r"vue\.min\.js", r"__vue__"],
        "Angular": [r"angular", r"ng-version"],
        "Next.js": [r"_next", r"__next"],
        "jQuery": [r"jquery", r"jquery\.min\.js"],
        
        # CSS Frameworks
        "Bootstrap": [r"bootstrap", r"bootstrap\.min"],
        "Tailwind CSS": [r"tailwind"],
        
        # Backend
        "PHP": [r"\.php", r"x-powered-by.*php"],
        "Laravel": [r"laravel"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "ASP.NET": [r"asp\.net", r"__viewstate"],
        
        # Web Servers
        "Nginx": [r"nginx"],
        "Apache": [r"apache"],
        "Cloudflare": [r"cloudflare", r"cf-ray"],
        
        # Analytics
        "Google Analytics": [r"google-analytics\.com", r"gtag", r"googletagmanager"],
        "Facebook Pixel": [r"facebook\.net", r"fbq\("],
        
        # Security
        "reCAPTCHA": [r"recaptcha", r"grecaptcha"],
    }
    
    async def scan(self, url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        found_tech = set()
        
        try:
            client = await http_pool.get_client("tech")
            response = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
            })
            
            content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            for tech, patterns in self.SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, content) or re.search(pattern, headers_str):
                        found_tech.add(tech)
                        break
            
            # Categorize technologies
            categories = {
                "cms": [],
                "javascript": [],
                "css": [],
                "backend": [],
                "server": [],
                "analytics": [],
                "security": []
            }
            
            category_map = {
                "WordPress": "cms", "Drupal": "cms", "Joomla": "cms", "Shopify": "cms", "Wix": "cms",
                "React": "javascript", "Vue.js": "javascript", "Angular": "javascript", 
                "Next.js": "javascript", "jQuery": "javascript",
                "Bootstrap": "css", "Tailwind CSS": "css",
                "PHP": "backend", "Laravel": "backend", "Django": "backend", "ASP.NET": "backend",
                "Nginx": "server", "Apache": "server", "Cloudflare": "server",
                "Google Analytics": "analytics", "Facebook Pixel": "analytics",
                "reCAPTCHA": "security"
            }
            
            for tech in found_tech:
                cat = category_map.get(tech, "other")
                if cat in categories:
                    categories[cat].append(tech)
            
            return self._success({
                "technologies": sorted(found_tech),
                "count": len(found_tech),
                "categories": categories,
            })
            
        except Exception as e:
            return self._error(str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# SecurityTrails Scanner - Subdomain discovery
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityTrailsScanner(AsyncScannerStrategy):
    """SecurityTrails subdomain and DNS history - Premium API"""
    
    name = "SecurityTrails"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def scan(self, url: str) -> dict:
        if not self.api_key:
            return self._no_key({"subdomains": []})
        
        hostname = NetworkUtils.get_hostname(url)
        base_domain = NetworkUtils.get_base_domain(hostname)
        
        if not base_domain:
            return self._error("Invalid domain", {"subdomains": []})
        
        try:
            limiter = http_pool.get_limiter("securitytrails")
            async with limiter:
                client = await http_pool.get_client("securitytrails")
                headers = {"APIKEY": self.api_key, "Accept": "application/json"}
                
                # Get subdomains (paginated for more results)
                subdomains = []
                subdomain_count = 0
                
                # First page
                sub_response = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{base_domain}/subdomains",
                    headers=headers,
                    params={"children_only": "false", "include_inactive": "true"}
                )
                
                if sub_response.status_code == 200:
                    data = sub_response.json()
                    subdomain_list = data.get('subdomains', [])
                    subdomain_count = data.get('subdomain_count', len(subdomain_list))
                    subdomains = [f"{sub}.{base_domain}" for sub in subdomain_list[:200]]
                
                # Get domain info
                domain_response = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{base_domain}",
                    headers=headers
                )
                
                domain_info = {"apex_domain": base_domain}
                if domain_response.status_code == 200:
                    data = domain_response.json()
                    current_dns = data.get('current_dns', {})
                    domain_info = {
                        "apex_domain": base_domain,
                        "alexa_rank": data.get('alexa_rank'),
                        "a_records": [r.get('ip') for r in current_dns.get('a', {}).get('values', [])][:10],
                        "mx_records": [r.get('hostname') for r in current_dns.get('mx', {}).get('values', [])][:10],
                        "ns_records": [r.get('nameserver') for r in current_dns.get('ns', {}).get('values', [])][:10],
                        "txt_records": [r.get('value', '')[:100] for r in current_dns.get('txt', {}).get('values', [])][:5],
                    }
                
                # Get DNS history for risk assessment
                dns_changes = 0
                historical_ips = []
                try:
                    history_response = await client.get(
                        f"https://api.securitytrails.com/v1/history/{base_domain}/dns/a",
                        headers=headers
                    )
                    if history_response.status_code == 200:
                        records = history_response.json().get('records', [])
                        dns_changes = len(records)
                        for record in records[:10]:
                            for val in record.get('values', []):
                                ip = val.get('ip')
                                if ip:
                                    historical_ips.append(ip)
                except Exception:
                    pass
                
                # Risk: many DNS changes could indicate suspicious activity
                risk = 15 if dns_changes > 20 else 0
                
                return self._success({
                    "subdomains": subdomains,
                    "subdomain_count": subdomain_count,
                    "domain_info": domain_info,
                    "dns_history_changes": dns_changes,
                    "historical_ips": list(set(historical_ips))[:20],
                    "risk_contribution": risk,
                })
                
        except Exception as e:
            return self._error(str(e), {"subdomains": []})

# ═══════════════════════════════════════════════════════════════════════════════
# Chaos Scanner - ProjectDiscovery subdomain discovery
# ═══════════════════════════════════════════════════════════════════════════════

class ChaosScanner(AsyncScannerStrategy):
    """ProjectDiscovery Chaos API for subdomain discovery - Bug Bounty Data"""
    
    name = "Chaos"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def scan(self, url: str) -> dict:
        if not self.api_key:
            return self._no_key({"subdomains": []})
        
        hostname = NetworkUtils.get_hostname(url)
        base_domain = NetworkUtils.get_base_domain(hostname)
        
        if not base_domain:
            return self._error("Invalid domain", {"subdomains": []})
        
        try:
            limiter = http_pool.get_limiter("chaos")
            async with limiter:
                client = await http_pool.get_client("chaos")
                headers = {"Authorization": self.api_key}
                
                response = await client.get(
                    f"https://dns.projectdiscovery.io/dns/{base_domain}/subdomains",
                    headers=headers,
                    timeout=20.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    subdomains = data.get('subdomains', [])
                    # Get all subdomains, not just first 100
                    full_subdomains = [f"{sub}.{base_domain}" for sub in subdomains[:500]]
                    
                    return self._success({
                        "subdomains": full_subdomains,
                        "subdomain_count": len(subdomains),
                        "base_domain": base_domain,
                        "is_program": data.get('is_program', False),
                    })
                elif response.status_code == 404:
                    return {
                        "source": self.name,
                        "status": "Domain Not Indexed",
                        "subdomains": [],
                        "subdomain_count": 0,
                        "risk_contribution": 0
                    }
                else:
                    return self._error(f"HTTP {response.status_code}", {"subdomains": []})
                    
        except Exception as e:
            return self._error(str(e), {"subdomains": []})

# ═══════════════════════════════════════════════════════════════════════════════
# NVD Scanner - National Vulnerability Database
# ═══════════════════════════════════════════════════════════════════════════════

class NVDScanner(AsyncScannerStrategy):
    """NVD (National Vulnerability Database) Scanner for CVE lookup"""
    
    name = "NVD"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    # Technology fingerprints used to build CPE keyword searches
    _TECH_FINGERPRINTS = {
        # (header_name, keyword_in_value): search_term_for_NVD
        "server": {
            "apache": "apache http server",
            "nginx": "nginx",
            "iis": "microsoft iis",
            "litespeed": "litespeed web server",
            "lighttpd": "lighttpd",
            "openresty": "openresty",
            "tomcat": "apache tomcat",
            "jetty": "jetty",
            "gunicorn": "gunicorn",
            "caddy": "caddy",
        },
        "x-powered-by": {
            "php": "php",
            "asp.net": "asp.net",
            "express": "node.js express",
            "django": "django",
            "rails": "ruby on rails",
            "laravel": "laravel",
            "next.js": "next.js",
            "java": "java",
        },
        "x-generator": {
            "wordpress": "wordpress",
            "drupal": "drupal",
            "joomla": "joomla",
        },
        "x-cms": {
            "wordpress": "wordpress",
            "drupal": "drupal",
        },
    }

    async def scan(self, url: str) -> dict:
        """Query NVD for CVEs tied to the actual server technologies detected via HTTP headers.
        This replaces the previous hostname-keyword approach which produced irrelevant results.
        """
        hostname = NetworkUtils.get_hostname(url)
        if not hostname:
            return self._error("Invalid host", {"vulnerabilities": []})

        try:
            # ── Step 1: detect technologies from HTTP response headers ─────────
            search_terms: list[str] = []
            detected_techs: list[str] = []
            try:
                http_client = await http_pool.get_client("tech")
                for proto in ("https", "http"):
                    try:
                        resp = await http_client.get(
                            f"{proto}://{hostname}",
                            timeout=10.0,
                            follow_redirects=True,
                        )
                        hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}

                        # Check each header fingerprint
                        for hdr_name, keyword_map in self._TECH_FINGERPRINTS.items():
                            hdr_val = hdrs.get(hdr_name, "")
                            for keyword, nvd_term in keyword_map.items():
                                if keyword in hdr_val:
                                    if nvd_term not in search_terms:
                                        search_terms.append(nvd_term)
                                        detected_techs.append(keyword)
                                    break

                        # Also check content for CMS/framework hints
                        body = resp.text[:8000].lower()
                        content_hints = {
                            "wp-content": "wordpress",
                            "wp-json":    "wordpress",
                            "joomla":     "joomla",
                            "drupal.js":  "drupal",
                            "laravel":    "laravel",
                            "django":     "django",
                            "struts":     "apache struts",
                            "spring":     "spring framework",
                        }
                        for marker, nvd_term in content_hints.items():
                            if marker in body and nvd_term not in search_terms:
                                search_terms.append(nvd_term)
                                detected_techs.append(marker)

                        break  # got a successful response — stop trying protocols
                    except Exception:
                        continue
            except Exception:
                pass

            if not search_terms:
                return self._success({
                    "vulnerabilities": [],
                    "total_found": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "detected_techs": [],
                    "search_terms": [],
                })

            # ── Step 2: query NVD for each detected technology ─────────────────
            all_cves: list[dict] = []
            seen_ids: set[str] = set()
            limiter = http_pool.get_limiter("nvd")
            nvd_client = await http_pool.get_client("nvd")
            nvd_headers = {"User-Agent": "SecureLens/3.0"}
            if self.api_key:
                nvd_headers["apiKey"] = self.api_key

            for term in search_terms:
                try:
                    async with limiter:
                        response = await nvd_client.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": term, "resultsPerPage": 20},
                            headers=nvd_headers,
                            timeout=20.0,
                        )
                        if response.status_code == 200:
                            for vuln in response.json().get("vulnerabilities", []):
                                cve = vuln.get("cve", {})
                                cve_id = cve.get("id", "")
                                if not cve_id or cve_id in seen_ids:
                                    continue
                                seen_ids.add(cve_id)

                                desc = ""
                                for d in cve.get("descriptions", []):
                                    if d.get("lang") == "en":
                                        desc = d.get("value", "")[:300]
                                        break

                                metrics = cve.get("metrics", {})
                                severity = "Unknown"
                                cvss_score = None
                                for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                    if ver in metrics and metrics[ver]:
                                        cd = metrics[ver][0].get("cvssData", {})
                                        cvss_score = cd.get("baseScore")
                                        severity = cd.get("baseSeverity", "Unknown")
                                        break

                                all_cves.append({
                                    "id": cve_id,
                                    "description": desc,
                                    "severity": severity,
                                    "cvss": cvss_score,
                                    "technology": term,
                                    "source": "NVD",
                                })
                        await asyncio.sleep(CONFIG.nvd_rate_limit)
                except Exception:
                    continue

            critical_count = sum(1 for c in all_cves if c.get("severity") == "CRITICAL")
            high_count     = sum(1 for c in all_cves if c.get("severity") == "HIGH")
            risk = 0
            if critical_count > 0:
                risk = min(30 + critical_count * 10, 50)
            elif high_count > 0:
                risk = min(15 + high_count * 5, 30)

            return self._success({
                "vulnerabilities": all_cves,
                "total_found":     len(all_cves),
                "critical_count":  critical_count,
                "high_count":      high_count,
                "detected_techs":  detected_techs,
                "search_terms":    search_terms,
                "risk_contribution": risk,
            })

        except Exception as e:
            return self._error(str(e), {"vulnerabilities": []})

# ═══════════════════════════════════════════════════════════════════════════════
# Subdomain Discovery - Multiple sources (Enhanced)
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainDiscoveryScanner(AsyncScannerStrategy):
    """Enhanced subdomain discovery using multiple free sources"""
    
    name = "SubdomainDiscovery"
    requires_api_key = False
    
    # Expanded common subdomain prefixes
    COMMON_PREFIXES = [
        # Standard
        'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
        'app', 'portal', 'secure', 'vpn', 'remote', 'cdn', 'static',
        'blog', 'shop', 'store', 'mobile', 'm', 'beta', 'demo', 'login',
        'auth', 'sso', 'dashboard', 'panel', 'webmail', 'ns1', 'ns2',
        # Infrastructure
        'mx', 'mx1', 'mx2', 'smtp', 'pop', 'imap', 'exchange', 'autodiscover',
        'gateway', 'proxy', 'fw', 'firewall', 'router', 'switch', 'dns',
        # Development & CI/CD
        'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'build',
        'deploy', 'release', 'qa', 'uat', 'sandbox', 'preview', 'canary',
        # Services
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
        'search', 'solr', 'kafka', 'rabbitmq', 'queue', 'cache', 'memcached',
        # Cloud & Hosting
        'aws', 'azure', 'gcp', 'cloud', 's3', 'storage', 'backup', 'dr',
        'origin', 'edge', 'lb', 'loadbalancer', 'node', 'worker', 'cluster',
        # Applications
        'cms', 'wordpress', 'wp', 'jira', 'confluence', 'wiki', 'docs',
        'helpdesk', 'support', 'ticket', 'crm', 'erp', 'hr', 'internal',
        # Security
        'siem', 'ids', 'waf', 'scan', 'monitor', 'log', 'logs', 'metrics',
        'grafana', 'kibana', 'splunk', 'nagios', 'zabbix', 'prometheus',
        # Misc
        'media', 'img', 'images', 'assets', 'files', 'download', 'upload',
        'video', 'stream', 'live', 'ws', 'websocket', 'socket', 'realtime',
        'legacy', 'old', 'new', 'v1', 'v2', 'v3', 'api2', 'api3',
        'web', 'www1', 'www2', 'www3', 'server', 'server1', 'server2',
        'host', 'host1', 'host2', 'vps', 'vps1', 'vps2', 'prod', 'production'
    ]
    
    async def scan(self, url: str) -> dict:
        hostname = NetworkUtils.get_hostname(url)
        base_domain = NetworkUtils.get_base_domain(hostname)
        
        if not base_domain:
            return self._error("Invalid domain", {"subdomains": []})
        
        subdomains = set()
        subdomains.add(hostname)
        source_counts = {}
        
        try:
            client = await http_pool.get_client("subdomain")
            
            # Source 1: crt.sh Certificate Transparency (expanded)
            crt_count = await self._fetch_crtsh(client, base_domain, subdomains)
            source_counts["crt.sh"] = crt_count
            
            # Source 2: HackerTarget API (free, no key required)
            ht_count = await self._fetch_hackertarget(client, base_domain, subdomains)
            source_counts["HackerTarget"] = ht_count
            
            # Source 3: AlienVault OTX (free, no key required for passive DNS)
            otx_count = await self._fetch_alienvault(client, base_domain, subdomains)
            source_counts["AlienVault"] = otx_count
            
            # Source 4: RapidDNS (free web scraping)
            rapid_count = await self._fetch_rapiddns(client, base_domain, subdomains)
            source_counts["RapidDNS"] = rapid_count
            
            # Source 5: ThreatMiner (free API)
            tm_count = await self._fetch_threatminer(client, base_domain, subdomains)
            source_counts["ThreatMiner"] = tm_count
            
            # Source 6: URLScan.io (free search)
            urlscan_count = await self._fetch_urlscan(client, base_domain, subdomains)
            source_counts["URLScan"] = urlscan_count
            
            # Source 7: Common prefix enumeration
            for prefix in self.COMMON_PREFIXES:
                subdomains.add(f"{prefix}.{base_domain}")
            source_counts["Wordlist"] = len(self.COMMON_PREFIXES)
            
            # Resolve and verify subdomains
            valid_subdomains = await self._verify_subdomains(subdomains, hostname)
            
            # Create simple list of subdomain strings for template compatibility
            subdomain_list = [v["subdomain"] for v in valid_subdomains]
            
            return self._success({
                "base_domain": base_domain,
                "subdomains": subdomain_list,
                "total_found": len(subdomains),
                "valid_subdomains": valid_subdomains,
                "valid_count": len(valid_subdomains),
                "sources": source_counts,
            })
            
        except Exception as e:
            return self._error(str(e), {"subdomains": []})
    
    async def _fetch_crtsh(self, client, base_domain: str, subdomains: set) -> int:
        """Fetch from crt.sh Certificate Transparency logs"""
        count = 0
        try:
            response = await client.get(
                f"https://crt.sh/?q=%.{base_domain}&output=json",
                timeout=20.0
            )
            if response.status_code == 200:
                certs = response.json()
                for cert in certs[:500]:  # Increased from 200
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(base_domain) and '*' not in sub and sub not in subdomains:
                            subdomains.add(sub)
                            count += 1
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        return count
    
    async def _fetch_hackertarget(self, client, base_domain: str, subdomains: set) -> int:
        """Fetch from HackerTarget free API"""
        count = 0
        try:
            response = await client.get(
                f"https://api.hackertarget.com/hostsearch/?q={base_domain}",
                timeout=15.0
            )
            if response.status_code == 200 and "error" not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(base_domain) and subdomain not in subdomains:
                            subdomains.add(subdomain)
                            count += 1
        except Exception as e:
            logger.debug(f"HackerTarget error: {e}")
        return count
    
    async def _fetch_alienvault(self, client, base_domain: str, subdomains: set) -> int:
        """Fetch from AlienVault OTX passive DNS"""
        count = 0
        try:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{base_domain}/passive_dns",
                timeout=15.0
            )
            if response.status_code == 200:
                data = response.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '').lower()
                    if hostname.endswith(base_domain) and hostname not in subdomains:
                        subdomains.add(hostname)
                        count += 1
        except Exception as e:
            logger.debug(f"AlienVault error: {e}")
        return count
    
    async def _fetch_rapiddns(self, client, base_domain: str, subdomains: set) -> int:
        """Fetch from RapidDNS"""
        count = 0
        try:
            response = await client.get(
                f"https://rapiddns.io/subdomain/{base_domain}?full=1",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
            )
            if response.status_code == 200:
                # Parse HTML for subdomains
                import re
                pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(base_domain)}'
                matches = re.findall(pattern, response.text)
                for match in set(response.text.split()):
                    if base_domain in match:
                        # Clean and extract subdomain
                        clean = re.search(rf'([a-zA-Z0-9][-a-zA-Z0-9.]*\.{re.escape(base_domain)})', match)
                        if clean:
                            sub = clean.group(1).lower()
                            if sub not in subdomains and not sub.startswith('.'):
                                subdomains.add(sub)
                                count += 1
        except Exception as e:
            logger.debug(f"RapidDNS error: {e}")
        return count
    
    async def _fetch_threatminer(self, client, base_domain: str, subdomains: set) -> int:
        """Fetch from ThreatMiner API"""
        count = 0
        try:
            response = await client.get(
                f"https://api.threatminer.org/v2/domain.php?q={base_domain}&rt=5",
                timeout=15.0
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status_code') == '200':
                    for sub in data.get('results', []):
                        sub = sub.lower()
                        if sub.endswith(base_domain) and sub not in subdomains:
                            subdomains.add(sub)
                            count += 1
        except Exception as e:
            logger.debug(f"ThreatMiner error: {e}")
        return count
    
    async def _fetch_urlscan(self, client, base_domain: str, subdomains: set) -> int:
        """Fetch from URLScan.io search"""
        count = 0
        try:
            response = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{base_domain}",
                timeout=15.0
            )
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', [])[:100]:
                    page = result.get('page', {})
                    domain = page.get('domain', '').lower()
                    if domain.endswith(base_domain) and domain not in subdomains:
                        subdomains.add(domain)
                        count += 1
        except Exception as e:
            logger.debug(f"URLScan error: {e}")
        return count
    
    async def _verify_subdomains(self, subdomains: set, main_host: str) -> list:
        """Verify subdomains by DNS resolution"""
        valid_subdomains = []
        
        async def check_subdomain(sub):
            try:
                ip = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyname, sub),
                    timeout=2.0
                )
                return {"subdomain": sub, "ip": ip, "valid": True}
            except:
                return None
        
        # Prioritize main host, then sort by length (shorter often more important)
        sorted_subs = sorted(subdomains, key=lambda x: (x != main_host, len(x)))
        
        # Check up to max_subdomain_resolve subdomains
        tasks = [check_subdomain(sub) for sub in sorted_subs[:CONFIG.max_subdomain_resolve]]
        results = await gather_in_batches(tasks, batch_size=20, return_exceptions=True)
        
        for result in results:
            if result and isinstance(result, dict):
                valid_subdomains.append(result)
        
        return valid_subdomains

# ═══════════════════════════════════════════════════════════════════════════════
# Comprehensive CVE Scanner - Multi-source vulnerability detection
# ═══════════════════════════════════════════════════════════════════════════════

class ComprehensiveCVEScanner(AsyncScannerStrategy):
    """Multi-source CVE scanner with subdomain scanning and per-subdomain analysis"""
    
    name = "CVEAnalysis"
    
    TECH_KEYWORDS = {
        "apache": ["apache http server", "httpd"], "nginx": ["nginx"],
        "wordpress": ["wordpress", "wp-content"], "php": ["php", "x-powered-by: php"],
        "mysql": ["mysql", "mariadb"], "postgresql": ["postgresql", "postgres"],
        "tomcat": ["apache tomcat", "catalina"], "jenkins": ["jenkins", "x-jenkins"],
        "openssl": ["openssl"], "jquery": ["jquery"],
        "node": ["node.js", "express"], "django": ["django", "csrfmiddlewaretoken"],
        "laravel": ["laravel"], "iis": ["microsoft-iis", "asp.net"],
        "spring": ["spring", "x-application-context"],
        "elasticsearch": ["elasticsearch"], "redis": ["redis"],
        "mongodb": ["mongodb"], "docker": ["docker"],
        "kubernetes": ["kubernetes", "k8s"],
    }
    
    # Common vulnerable ports to check
    VULN_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        27017: "MongoDB"
    }
    
    def __init__(self, shodan_key: str, nvd_key: str = ""):
        self.shodan_key = shodan_key
        self.nvd_key = nvd_key
    
    async def scan(self, url: str) -> dict:
        host = NetworkUtils.get_hostname(url)
        if not host:
            return self._error("Invalid hostname")
        
        all_vulns = {}
        scanned_ips = {}
        scanned_subdomains = []
        detected_tech = []
        cve_sources = {}
        subdomain_security = {}  # Per-subdomain security analysis
        
        try:
            # Step 1: Discover subdomains from multiple sources
            subdomains = await self._discover_subdomains(host)
            
            # Step 2: Resolve IPs for ALL discovered subdomains (no cap here)
            subdomain_ips = await self._resolve_ips(subdomains, host)
            
            # Step 3: Perform per-subdomain security analysis (detects tech per subdomain)
            subdomain_security = await self._analyze_subdomains(subdomain_ips, host)
            
            # Build IP → subdomain mapping
            for subdomain, ip in subdomain_ips.items():
                if ip:
                    if ip not in scanned_ips:
                        scanned_ips[ip] = {
                            "subdomains": [], "is_main": subdomain == host,
                            "ports": [], "org": "Unknown", "vulns_count": 0,
                            "services": [], "os": None
                        }
                    scanned_ips[ip]["subdomains"].append(subdomain)
            
            # Step 4: Shodan — two complementary approaches:
            #   4a) Domain search: finds all Shodan-indexed hosts for the domain
            #       (catches subdomains not found via DNS, returns CVEs immediately)
            #   4b) Per-IP host scan: richer per-service CVE data for resolved IPs
            # Run them together so the vulnerability stage keeps full coverage
            # without paying the cost of serial Shodan passes.
            if self.shodan_key:
                base_domain = NetworkUtils.get_base_domain(host)
                await asyncio.gather(
                    self._shodan_domain_search(base_domain, all_vulns, cve_sources),
                    self._scan_shodan(scanned_ips, all_vulns, cve_sources),
                )
            
            # Step 5: Technology-based NVD lookup
            #   Run for the main host PLUS every subdomain that detected technologies.
            #   Use parallel tasks to avoid serial NVD rate-limit stalls.
            if self.nvd_key:
                # Main host tech scan
                await self._scan_nvd_tech(host, all_vulns, detected_tech, cve_sources)

                # Collect technologies discovered on subdomains
                subdomain_techs: set = set()
                for sub, analysis in subdomain_security.items():
                    for tech in analysis.get("technologies", []):
                        subdomain_techs.add(tech.lower())

                # Run NVD lookups for any tech not already covered by the main host scan
                covered = {t["name"].lower() if isinstance(t, dict) else t.lower() for t in detected_tech}
                new_techs = [t for t in subdomain_techs if t not in covered]

                if new_techs:
                    # Batch additional tech searches directly against NVD
                    await self._scan_nvd_extra_techs(new_techs, all_vulns, cve_sources)
            
            # Step 6: Additional port-based vulnerability detection
            await self._port_vuln_scan(scanned_ips, all_vulns, cve_sources)
            
            # Step 7: Enrich CVE details from NVD (parallel batches, not serial)
            if all_vulns and self.nvd_key:
                await self._enrich_cves(all_vulns)
            
            # Build subdomain results with security analysis
            for subdomain in list(subdomains)[:CONFIG.max_subdomain_scan]:
                ip = subdomain_ips.get(subdomain)
                security = subdomain_security.get(subdomain, {})
                info = {
                    "subdomain": subdomain,
                    "ip": ip,
                    "is_main": subdomain == host,
                    "vuln_count": 0,
                    "security_score": security.get("score", 0),
                    "ssl_valid": security.get("ssl_valid", None),
                    "http_status": security.get("http_status"),
                    "server": security.get("server"),
                    "technologies": security.get("technologies", []),
                    "security_headers": security.get("security_headers", {}),
                    "issues": security.get("issues", [])
                }
                if ip and ip in scanned_ips:
                    info["vuln_count"] = scanned_ips[ip].get("vulns_count", 0)
                    info["ports"] = scanned_ips[ip].get("ports", [])[:10]
                    info["org"] = scanned_ips[ip].get("org", "Unknown")
                    info["services"] = scanned_ips[ip].get("services", [])[:5]
                    info["os"] = scanned_ips[ip].get("os")
                scanned_subdomains.append(info)
            
            # Calculate risk
            critical = sum(1 for v in all_vulns.values() if v.get('severity') == 'CRITICAL')
            high = sum(1 for v in all_vulns.values() if v.get('severity') == 'HIGH')
            medium = sum(1 for v in all_vulns.values() if v.get('severity') == 'MEDIUM')
            low = sum(1 for v in all_vulns.values() if v.get('severity') == 'LOW')
            
            # Calculate total issues across subdomains
            total_subdomain_issues = sum(len(s.get("issues", [])) for s in scanned_subdomains)
            
            risk = min(critical * 25 + high * 15 + medium * 5 + low * 2 + total_subdomain_issues * 2, 100)
            
            # Sort vulnerabilities
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'Unknown': 4}
            sorted_vulns = sorted(
                all_vulns.values(),
                key=lambda x: (severity_order.get(x.get('severity', 'Unknown'), 4), -(x.get('cvss') or 0))
            )
            
            return {
                "source": "CVEAnalysis",
                "status": "Found" if all_vulns else "Clean",
                "total_vulnerabilities": len(all_vulns),
                "critical_count": critical,
                "high_count": high,
                "medium_count": medium,
                "low_count": low,
                "vulnerabilities": sorted_vulns,
                "scanned_ips": list(scanned_ips.keys()),
                "ip_details": scanned_ips,
                "scanned_subdomains": scanned_subdomains,
                "total_subdomains_scanned": len(scanned_subdomains),
                "total_subdomain_issues": total_subdomain_issues,
                "detected_technologies": detected_tech,
                "cve_sources": cve_sources,
                "subdomain_security_summary": {
                    "total_scanned": len(scanned_subdomains),
                    "with_ssl": sum(1 for s in scanned_subdomains if s.get("ssl_valid")),
                    "with_issues": sum(1 for s in scanned_subdomains if s.get("issues")),
                    "avg_security_score": round(sum(s.get("security_score", 0) for s in scanned_subdomains) / max(len(scanned_subdomains), 1))
                },
                "risk_contribution": risk
            }
            
        except Exception as e:
            logger.error(f"CVEAnalysis error: {e}")
            return self._error(str(e), {"vulnerabilities": []})
    
    async def _analyze_subdomains(self, subdomain_ips: dict, main_host: str) -> dict:
        """Perform per-subdomain security analysis"""
        results = {}
        
        async def analyze_single(subdomain: str, ip: str):
            """Analyze a single subdomain for security issues"""
            analysis = {
                "score": 100,
                "ssl_valid": None,
                "http_status": None,
                "server": None,
                "technologies": [],
                "security_headers": {},
                "issues": []
            }
            
            try:
                client = await http_pool.get_client("subdomain_analysis")
                
                # Try HTTPS first
                for protocol in ["https", "http"]:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = await client.get(url, timeout=8.0, follow_redirects=True)
                        analysis["http_status"] = response.status_code
                        analysis["ssl_valid"] = (protocol == "https")
                        
                        # Extract server header
                        analysis["server"] = response.headers.get("server", "Unknown")
                        
                        # Check security headers
                        security_headers = {
                            "strict-transport-security": response.headers.get("strict-transport-security"),
                            "content-security-policy": response.headers.get("content-security-policy"),
                            "x-frame-options": response.headers.get("x-frame-options"),
                            "x-content-type-options": response.headers.get("x-content-type-options"),
                            "x-xss-protection": response.headers.get("x-xss-protection"),
                            "referrer-policy": response.headers.get("referrer-policy"),
                            "permissions-policy": response.headers.get("permissions-policy"),
                        }
                        analysis["security_headers"] = {k: v for k, v in security_headers.items() if v}
                        
                        # Detect technologies from headers
                        headers_lower = str(response.headers).lower()
                        content_lower = response.text[:5000].lower() if response.text else ""
                        
                        tech_detected = []
                        for tech, keywords in self.TECH_KEYWORDS.items():
                            for kw in [tech.lower()] + keywords:
                                if kw in headers_lower or kw in content_lower:
                                    tech_detected.append(tech)
                                    break
                        analysis["technologies"] = list(set(tech_detected))
                        
                        # Calculate security issues
                        if protocol == "http":
                            analysis["issues"].append("No HTTPS")
                            analysis["score"] -= 25
                        
                        if not security_headers.get("strict-transport-security"):
                            analysis["issues"].append("Missing HSTS")
                            analysis["score"] -= 10
                        
                        if not security_headers.get("content-security-policy"):
                            analysis["issues"].append("Missing CSP")
                            analysis["score"] -= 10
                        
                        if not security_headers.get("x-frame-options"):
                            analysis["issues"].append("Missing X-Frame-Options")
                            analysis["score"] -= 5
                        
                        if not security_headers.get("x-content-type-options"):
                            analysis["issues"].append("Missing X-Content-Type-Options")
                            analysis["score"] -= 5
                        
                        # Check for exposed server version
                        server_val = analysis["server"].lower()
                        if any(v in server_val for v in ["/", ".", "-"]) and any(c.isdigit() for c in server_val):
                            analysis["issues"].append("Server version exposed")
                            analysis["score"] -= 5
                        
                        analysis["score"] = max(0, analysis["score"])
                        break
                        
                    except Exception:
                        continue
                        
            except Exception as e:
                analysis["issues"].append(f"Connection failed: {str(e)[:50]}")
                analysis["score"] = 0
            
            return subdomain, analysis
        
        # Analyze subdomains in parallel (limit concurrency)
        tasks = []
        for subdomain, ip in list(subdomain_ips.items())[:CONFIG.max_subdomain_scan]:
            if ip:  # Only analyze resolved subdomains
                tasks.append(analyze_single(subdomain, ip))
        
        if tasks:
            analyzed = await gather_in_batches(tasks, batch_size=6, return_exceptions=True)
            for result in analyzed:
                if isinstance(result, tuple):
                    subdomain, analysis = result
                    results[subdomain] = analysis
        
        return results
    
    async def _port_vuln_scan(self, scanned_ips: dict, all_vulns: dict, cve_sources: dict):
        """Check for common vulnerable services based on ports"""
        # Port-based vulnerability indicators
        risky_ports = {
            23: {"name": "Telnet", "severity": "HIGH", "desc": "Telnet service detected - unencrypted protocol"},
            21: {"name": "FTP", "severity": "MEDIUM", "desc": "FTP service detected - consider using SFTP"},
            445: {"name": "SMB", "severity": "HIGH", "desc": "SMB port exposed - potential ransomware target"},
            3389: {"name": "RDP", "severity": "HIGH", "desc": "RDP exposed to internet - brute force risk"},
            6379: {"name": "Redis", "severity": "CRITICAL", "desc": "Redis exposed - often misconfigured without auth"},
            27017: {"name": "MongoDB", "severity": "CRITICAL", "desc": "MongoDB exposed - check for authentication"},
            9200: {"name": "Elasticsearch", "severity": "HIGH", "desc": "Elasticsearch exposed - data leak risk"},
            11211: {"name": "Memcached", "severity": "MEDIUM", "desc": "Memcached exposed - amplification attack risk"},
        }
        
        for ip, details in scanned_ips.items():
            ports = details.get("ports", [])
            for port in ports:
                if port in risky_ports:
                    vuln_info = risky_ports[port]
                    vuln_id = f"EXPOSED-{vuln_info['name'].upper()}-{ip}"
                    if vuln_id not in all_vulns:
                        all_vulns[vuln_id] = {
                            "id": vuln_id,
                            "description": f"{vuln_info['desc']} on {ip}:{port}",
                            "severity": vuln_info["severity"],
                            "cvss": 7.5 if vuln_info["severity"] == "CRITICAL" else 5.0,
                            "affected_ips": [ip],
                            "affected_subdomains": details.get("subdomains", []),
                            "source": "PortScan",
                            "port": port,
                            "service": vuln_info["name"]
                        }
                        cve_sources[vuln_id] = ["PortScan"]
                        details["vulns_count"] = details.get("vulns_count", 0) + 1
    
    async def _discover_subdomains(self, host: str) -> set:
        """Enhanced subdomain discovery via multiple sources"""
        subdomains = {host}
        base_domain = NetworkUtils.get_base_domain(host)
        
        try:
            client = await http_pool.get_client("subdomain")
            
            # Source 1: crt.sh Certificate Transparency (expanded limit)
            try:
                response = await client.get(
                    f"https://crt.sh/?q=%.{base_domain}&output=json",
                    timeout=15.0
                )
                if response.status_code == 200:
                    for cert in response.json()[:300]:
                        name = cert.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(base_domain) and '*' not in sub:
                                subdomains.add(sub)
            except:
                pass
            
            # Source 2: HackerTarget (free API)
            try:
                response = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={base_domain}",
                    timeout=10.0
                )
                if response.status_code == 200 and "error" not in response.text.lower():
                    for line in response.text.strip().split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip().lower()
                            if sub.endswith(base_domain):
                                subdomains.add(sub)
            except:
                pass
            
            # Source 3: AlienVault OTX
            try:
                response = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{base_domain}/passive_dns",
                    timeout=10.0
                )
                if response.status_code == 200:
                    data = response.json()
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname', '').lower()
                        if hostname.endswith(base_domain):
                            subdomains.add(hostname)
            except:
                pass
            
            # Source 4: ThreatMiner
            try:
                response = await client.get(
                    f"https://api.threatminer.org/v2/domain.php?q={base_domain}&rt=5",
                    timeout=10.0
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status_code') == '200':
                        for sub in data.get('results', []):
                            sub = sub.lower()
                            if sub.endswith(base_domain):
                                subdomains.add(sub)
            except:
                pass
            
        except Exception as e:
            logger.debug(f"Subdomain discovery error: {e}")
        
        # Common prefixes (expanded list)
        common_prefixes = [
            'www', 'mail', 'api', 'admin', 'dev', 'app', 'portal', 'cdn',
            'ftp', 'vpn', 'remote', 'staging', 'test', 'beta', 'demo',
            'blog', 'shop', 'store', 'mobile', 'm', 'login', 'auth',
            'secure', 'gateway', 'proxy', 'ns1', 'ns2', 'mx', 'smtp',
            'webmail', 'dashboard', 'panel', 'git', 'jenkins', 'ci',
            'db', 'mysql', 'postgres', 'redis', 'elastic', 'search',
            'media', 'img', 'static', 'assets', 'files', 'download'
        ]
        for prefix in common_prefixes:
            subdomains.add(f"{prefix}.{base_domain}")
        
        return subdomains
    
    async def _resolve_ips(self, subdomains: set, main_host: str) -> dict:
        """Resolve IPs for subdomains"""
        results = {}
        
        async def resolve(sub):
            try:
                ip = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyname, sub),
                    timeout=3.0
                )
                return (sub, ip)
            except:
                return (sub, None)
        
        # Sort by importance: main host first, then by length
        prioritized = [main_host] + sorted([s for s in subdomains if s != main_host], key=len)
        tasks = [resolve(sub) for sub in prioritized[:CONFIG.max_subdomain_resolve]]
        resolved = await gather_in_batches(tasks, batch_size=20, return_exceptions=True)
        
        for result in resolved:
            if isinstance(result, tuple):
                results[result[0]] = result[1]
        
        return results
    
    async def _shodan_domain_search(self, base_domain: str, all_vulns: dict, cve_sources: dict):
        """Query Shodan's search API for all hosts under base_domain.
        Returns CVEs for every Shodan-indexed host, including subdomains we may not
        have discovered through DNS, without needing to know their IPs in advance.
        Uses: GET /shodan/host/search?query=hostname:{domain}
        """
        if not self.shodan_key:
            return
        try:
            limiter = http_pool.get_limiter("shodan")
            client  = await http_pool.get_client("shodan")

            def _cvss_to_sev(score) -> str:
                try:
                    s = float(score)
                except Exception:
                    return "Unknown"
                if s >= 9.0: return "CRITICAL"
                if s >= 7.0: return "HIGH"
                if s >= 4.0: return "MEDIUM"
                return "LOW"

            page = 1
            total_processed = 0
            while page <= 5:  # max 5 pages = 500 hosts
                async with limiter:
                    try:
                        resp = await client.get(
                            "https://api.shodan.io/shodan/host/search",
                            params={
                                "key": self.shodan_key,
                                "query": f"hostname:{base_domain}",
                                "page": page,
                            },
                            timeout=20.0,
                        )
                        if resp.status_code != 200:
                            break

                        data  = resp.json()
                        items = data.get("matches", [])
                        if not items:
                            break

                        for item in items:
                            ip_str = item.get("ip_str", "")

                            # Extract CVEs from top-level vulns
                            item_vulns = item.get("vulns", {})
                            if isinstance(item_vulns, list):
                                item_vulns = {cid: {} for cid in item_vulns}

                            for cve_id, info in item_vulns.items():
                                if not cve_id.upper().startswith("CVE-"):
                                    continue
                                raw = info.get("cvss") or info.get("cvss3") or info.get("cvss2")
                                try:
                                    cvss_val = float(raw) if raw is not None else None
                                except Exception:
                                    cvss_val = None
                                desc     = info.get("summary") or info.get("description") or ""
                                verified = bool(info.get("verified", False))

                                if cve_id not in all_vulns:
                                    all_vulns[cve_id] = {
                                        "id": cve_id, "affected_ips": [], "affected_subdomains": [],
                                        "severity": _cvss_to_sev(cvss_val), "cvss": cvss_val,
                                        "description": str(desc)[:500],
                                        "source": "Shodan", "verified": verified,
                                    }
                                    cve_sources[cve_id] = ["Shodan"]
                                else:
                                    v = all_vulns[cve_id]
                                    if cvss_val is not None and v.get("cvss") is None:
                                        v["cvss"]     = cvss_val
                                        v["severity"] = _cvss_to_sev(cvss_val)
                                    if desc and not v.get("description"):
                                        v["description"] = str(desc)[:500]
                                    if verified:
                                        v["verified"] = True

                                if ip_str and ip_str not in all_vulns[cve_id]["affected_ips"]:
                                    all_vulns[cve_id]["affected_ips"].append(ip_str)

                        total_processed += len(items)
                        if len(items) < 100:  # last page
                            break
                        page += 1

                    except Exception as _pe:
                        logger.debug(f"Shodan domain search page {page} error: {_pe}")
                        break

            logger.info(f"Shodan domain search '{base_domain}': processed {total_processed} hosts")

        except Exception as e:
            logger.debug(f"Shodan domain search error: {e}")

    async def _scan_shodan(self, scanned_ips: dict, all_vulns: dict, cve_sources: dict):
        """Scan IPs with Shodan for CVEs.
        Extracts both the top-level vulns dict AND per-service data[].vulns so that
        CVSS scores and descriptions come directly from Shodan without requiring NVD.
        """
        def _cvss_to_severity(score) -> str:
            try:
                s = float(score)
            except (TypeError, ValueError):
                return "Unknown"
            if s >= 9.0: return "CRITICAL"
            if s >= 7.0: return "HIGH"
            if s >= 4.0: return "MEDIUM"
            return "LOW"

        try:
            limiter = http_pool.get_limiter("shodan")
            client = await http_pool.get_client("shodan")

            for ip in list(scanned_ips.keys()):  # no cap - scan ALL IPs
                async with limiter:
                    try:
                        response = await client.get(
                            f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": self.shodan_key}
                        )
                        if response.status_code != 200:
                            continue

                        data = response.json()
                        affected_subs = scanned_ips[ip].get("subdomains", [])

                        # Shodan returns vulns as dict {CVE-ID: {...}} or list [CVE-ID, ...]
                        top_vulns = data.get('vulns', {})
                        if isinstance(top_vulns, list):
                            top_vulns = {cid: {} for cid in top_vulns}

                        scanned_ips[ip].update({
                            "ports": sorted(data.get('ports', [])),
                            "org":   data.get('org', 'Unknown'),
                            "vulns_count": len(top_vulns),
                        })

                        def _upsert(cve_id: str, cvss=None, description="",
                                    verified=False, references=None):
                            """Create or improve a CVE entry without downgrading existing data."""
                            if not cve_id.upper().startswith("CVE-"):
                                return
                            if cve_id not in all_vulns:
                                all_vulns[cve_id] = {
                                    "id": cve_id,
                                    "affected_ips": [],
                                    "affected_subdomains": [],
                                    "severity": "Unknown",
                                    "cvss": None,
                                    "description": "",
                                    "source": "Shodan",
                                    "verified": False,
                                }
                                cve_sources[cve_id] = ["Shodan"]

                            v = all_vulns[cve_id]
                            if cvss is not None and v.get("cvss") is None:
                                v["cvss"] = cvss
                                v["severity"] = _cvss_to_severity(cvss)
                            if description and not v.get("description"):
                                v["description"] = str(description)[:500]
                            if verified:
                                v["verified"] = True
                            if references:
                                v.setdefault("references", []).extend(references)
                            if ip not in v["affected_ips"]:
                                v["affected_ips"].append(ip)
                            for sub in affected_subs:
                                if sub not in v["affected_subdomains"]:
                                    v["affected_subdomains"].append(sub)

                        # ── top-level vulns (may include cvss, summary, verified)
                        for cve_id, info in top_vulns.items():
                            raw = info.get("cvss") or info.get("cvss3") or info.get("cvss2")
                            try:
                                cvss_val = float(raw) if raw is not None else None
                            except (TypeError, ValueError):
                                cvss_val = None
                            _upsert(
                                cve_id,
                                cvss=cvss_val,
                                description=info.get("summary") or info.get("description") or "",
                                verified=bool(info.get("verified", False)),
                                references=info.get("references", []),
                            )

                        # ── per-service vulns — richest source inside data[]
                        for service in data.get("data", []):
                            svc_vulns = service.get("vulns", {})
                            if not isinstance(svc_vulns, dict):
                                continue
                            for cve_id, info in svc_vulns.items():
                                raw = info.get("cvss") or info.get("cvss3") or info.get("cvss2")
                                try:
                                    cvss_val = float(raw) if raw is not None else None
                                except (TypeError, ValueError):
                                    cvss_val = None
                                _upsert(
                                    cve_id,
                                    cvss=cvss_val,
                                    description=info.get("summary") or info.get("description") or "",
                                    verified=bool(info.get("verified", False)),
                                    references=info.get("references", []),
                                )

                    except Exception as _ip_err:
                        logger.debug(f"Shodan IP {ip} error: {_ip_err}")
                        continue

        except Exception as e:
            logger.error(f"Shodan CVE scan error: {e}")
    
    async def _scan_nvd_extra_techs(self, tech_names: list, all_vulns: dict, cve_sources: dict):
        """Run parallel NVD keyword searches for extra technologies found on subdomains."""
        if not tech_names or not self.nvd_key:
            return
        try:
            limiter = http_pool.get_limiter("nvd")
            client = await http_pool.get_client("nvd")
            headers = {"User-Agent": "SecureLens/3.0", "apiKey": self.nvd_key}
            async def _fetch_one(tech_name: str):
                async with limiter:
                    try:
                        resp = await client.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": tech_name, "resultsPerPage": 10},
                            headers=headers, timeout=20.0,
                        )
                        if resp.status_code == 200:
                            for vuln in resp.json().get("vulnerabilities", []):
                                cve = vuln.get("cve", {})
                                cve_id = cve.get("id", "")
                                if not cve_id or cve_id in all_vulns:
                                    continue
                                desc = ""
                                for d in cve.get("descriptions", []):
                                    if d.get("lang") == "en":
                                        desc = d.get("value", "")[:300]
                                        break
                                metrics = cve.get("metrics", {})
                                severity, cvss = "Unknown", None
                                for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                    if ver in metrics and metrics[ver]:
                                        cd = metrics[ver][0].get("cvssData", {})
                                        cvss = cd.get("baseScore")
                                        severity = cd.get("baseSeverity", "Unknown")
                                        break
                                all_vulns[cve_id] = {
                                    "id": cve_id, "description": desc, "severity": severity,
                                    "cvss": cvss, "technology": tech_name, "source": "NVD",
                                    "affected_subdomains": [], "affected_ips": [],
                                }
                                cve_sources[cve_id] = ["NVD"]
                        await asyncio.sleep(CONFIG.nvd_rate_limit)
                    except Exception as _e:
                        logger.debug(f"NVD extra tech error: {_e}")
            await asyncio.gather(*[_fetch_one(t) for t in tech_names])
        except Exception as e:
            logger.debug(f"NVD extra techs error: {e}")

    async def _scan_nvd_tech(self, host: str, all_vulns: dict, detected_tech: list, cve_sources: dict):
        """Detect server technologies (with version) from HTTP response, then query NVD
        using "product version" keyword searches for maximum precision.
        """
        import re as _re

        # Version extraction patterns for common Server header values
        VERSION_PATTERNS = [
            # "Apache/2.4.50"  "nginx/1.21.3"  "LiteSpeed/5.4"
            _re.compile(r'(apache)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(nginx)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(litespeed)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(iis)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(openssl)[\s/]([\d]+\.[\d]+\.?[\d]*[a-z]?)', _re.I),
            _re.compile(r'(tomcat)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(php)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            # "WordPress/6.4.2"  "Drupal/9.5"
            _re.compile(r'(wordpress)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(drupal)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
            _re.compile(r'(joomla)[\s/]([\d]+\.[\d]+\.?[\d]*)', _re.I),
        ]

        try:
            client = await http_pool.get_client("tech")
            response = None
            for proto in ("https", "http"):
                try:
                    response = await client.get(
                        f"{proto}://{host}",
                        timeout=10.0,
                        follow_redirects=True,
                    )
                    break
                except Exception:
                    continue

            if response is None:
                return

            # Collect all header values as one string for pattern matching
            all_headers_str = " ".join(
                f"{k}: {v}" for k, v in response.headers.items()
            ).lower()
            content_lower = response.text[:5000].lower() if response.text else ""

            # ── Extract versioned search terms ────────────────────────────────
            search_terms: list[tuple[str, str | None]] = []  # (product, version|None)
            seen_products: set = set()

            # First pass: version-aware extraction from all header values
            for hval in response.headers.values():
                for pat in VERSION_PATTERNS:
                    m = pat.search(hval)
                    if m:
                        product = m.group(1).lower()
                        version = m.group(2)
                        if product not in seen_products:
                            seen_products.add(product)
                            search_terms.append((product, version))
                            detected_tech.append({"name": product, "version": version, "source": "header-version"})

            # Second pass: name-only detection from TECH_KEYWORDS (no version found yet)
            for tech, keywords in self.TECH_KEYWORDS.items():
                if tech in seen_products:
                    continue
                in_h = any(kw in all_headers_str for kw in [tech] + keywords)
                in_c = any(kw in content_lower for kw in [tech] + keywords)
                if in_h or in_c:
                    seen_products.add(tech)
                    search_terms.append((tech, None))
                    detected_tech.append({"name": tech, "version": None, "source": "headers" if in_h else "content"})

            # ── Query NVD for each detected product ───────────────────────────
            limiter = http_pool.get_limiter("nvd")
            nvd_client = await http_pool.get_client("nvd")
            nvd_headers = {"User-Agent": "SecureLens/3.0", "apiKey": self.nvd_key}

            async def _nvd_search(keyword: str):
                async with limiter:
                    try:
                        resp = await nvd_client.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": keyword, "resultsPerPage": 20},
                            headers=nvd_headers,
                            timeout=20.0,
                        )
                        if resp.status_code == 200:
                            for vuln in resp.json().get("vulnerabilities", []):
                                cve = vuln.get("cve", {})
                                cve_id = cve.get("id", "")
                                if not cve_id or cve_id in all_vulns:
                                    continue
                                desc = ""
                                for d in cve.get("descriptions", []):
                                    if d.get("lang") == "en":
                                        desc = d.get("value", "")[:300]
                                        break
                                metrics = cve.get("metrics", {})
                                severity, cvss = "Unknown", None
                                for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                    if ver in metrics and metrics[ver]:
                                        cd = metrics[ver][0].get("cvssData", {})
                                        cvss = cd.get("baseScore")
                                        severity = cd.get("baseSeverity", "Unknown")
                                        break
                                all_vulns[cve_id] = {
                                    "id": cve_id, "description": desc, "severity": severity,
                                    "cvss": cvss, "technology": keyword, "source": "NVD",
                                    "affected_subdomains": [host], "affected_ips": [],
                                }
                                cve_sources[cve_id] = ["NVD"]
                        await asyncio.sleep(CONFIG.nvd_rate_limit)
                    except Exception as _e:
                        logger.debug(f"NVD search '{keyword}' error: {_e}")

            # Build keyword list: prefer "product version" when version known
            keywords_to_search: list[str] = []
            for product, version in search_terms:
                if version:
                    keywords_to_search.append(f"{product} {version}")  # precise
                keywords_to_search.append(product)                      # broad fallback

            # Deduplicate while preserving order (version-specific first)
            seen_kw: set = set()
            unique_kw = []
            for kw in keywords_to_search:
                if kw not in seen_kw:
                    seen_kw.add(kw)
                    unique_kw.append(kw)

            # Run all NVD searches in parallel
            await asyncio.gather(*[_nvd_search(kw) for kw in unique_kw])

        except Exception as e:
            logger.debug(f"NVD tech scan error: {e}")
    async def _scan_nvd_extra_techs(self, tech_names: list, all_vulns: dict, cve_sources: dict):
        """Run parallel NVD keyword searches for extra technologies found on subdomains."""
        if not tech_names or not self.nvd_key:
            return
        try:
            limiter = http_pool.get_limiter("nvd")
            client = await http_pool.get_client("nvd")
            headers = {"User-Agent": "SecureLens/3.0", "apiKey": self.nvd_key}
            async def _fetch_one(tech_name: str):
                async with limiter:
                    try:
                        resp = await client.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": tech_name, "resultsPerPage": 10},
                            headers=headers, timeout=20.0,
                        )
                        if resp.status_code == 200:
                            for vuln in resp.json().get("vulnerabilities", []):
                                cve = vuln.get("cve", {})
                                cve_id = cve.get("id", "")
                                if not cve_id or cve_id in all_vulns:
                                    continue
                                desc = ""
                                for d in cve.get("descriptions", []):
                                    if d.get("lang") == "en":
                                        desc = d.get("value", "")[:300]
                                        break
                                metrics = cve.get("metrics", {})
                                severity, cvss = "Unknown", None
                                for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                    if ver in metrics and metrics[ver]:
                                        cd = metrics[ver][0].get("cvssData", {})
                                        cvss = cd.get("baseScore")
                                        severity = cd.get("baseSeverity", "Unknown")
                                        break
                                all_vulns[cve_id] = {
                                    "id": cve_id, "description": desc, "severity": severity,
                                    "cvss": cvss, "technology": tech_name, "source": "NVD",
                                    "affected_subdomains": [], "affected_ips": [],
                                }
                                cve_sources[cve_id] = ["NVD"]
                        await asyncio.sleep(CONFIG.nvd_rate_limit)
                    except Exception as _e:
                        logger.debug(f"NVD extra tech error: {_e}")
            await asyncio.gather(*[_fetch_one(t) for t in tech_names])
        except Exception as e:
            logger.debug(f"NVD extra techs error: {e}")

    async def _scan_nvd_tech(self, host: str, all_vulns: dict, detected_tech: list, cve_sources: dict):
        """Scan for technology-based CVEs via NVD"""
        try:
            # First detect technologies
            client = await http_pool.get_client("tech")
            response = await client.get(f"http://{host}", timeout=10.0)
            content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            for tech, keywords in self.TECH_KEYWORDS.items():
                # Check if tech is in headers or content
                in_headers = any(kw in headers_str for kw in [tech] + keywords)
                in_content = any(kw in content for kw in [tech] + keywords)
                if in_headers or in_content:
                    detected_tech.append({
                        "name": tech,
                        "source": "headers" if in_headers else "content",
                        "version": None
                    })
            
            # Search NVD for detected technologies
            limiter = http_pool.get_limiter("nvd")
            nvd_client = await http_pool.get_client("nvd")
            headers = {"User-Agent": "SecureLens/3.0", "apiKey": self.nvd_key}
            
            for tech_info in detected_tech:
                tech_name = tech_info["name"] if isinstance(tech_info, dict) else tech_info
                async with limiter:
                    try:
                        response = await nvd_client.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={"keywordSearch": tech_name, "resultsPerPage": 10},
                            headers=headers
                        )
                        if response.status_code == 200:
                            for vuln in response.json().get('vulnerabilities', []):
                                cve = vuln.get('cve', {})
                                cve_id = cve.get('id', '')
                                if cve_id and cve_id not in all_vulns:
                                    desc = ""
                                    for d in cve.get('descriptions', []):
                                        if d.get('lang') == 'en':
                                            desc = d.get('value', '')[:300]
                                            break
                                    
                                    severity = "Unknown"
                                    cvss = None
                                    metrics = cve.get('metrics', {})
                                    for ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                                        if ver in metrics and metrics[ver]:
                                            cvss_data = metrics[ver][0].get('cvssData', {})
                                            cvss = cvss_data.get('baseScore')
                                            severity = cvss_data.get('baseSeverity', 'Unknown')
                                            break
                                    
                                    all_vulns[cve_id] = {
                                        "id": cve_id, "description": desc, "severity": severity,
                                        "cvss": cvss, "technology": tech_name, "source": "NVD"
                                    }
                                    cve_sources[cve_id] = ["NVD"]
                        
                        await asyncio.sleep(CONFIG.nvd_rate_limit)
                    except:
                        continue
        except Exception as e:
            logger.debug(f"NVD tech scan error: {e}")
    
    async def _enrich_cves(self, vulns: dict):
        """Enrich CVE data with NVD details. Uses parallel requests (semaphore-gated) so
        large CVE lists do not take prohibitively long. Runs KEV + EPSS checks after.
        """
        try:
            limiter = http_pool.get_limiter("nvd")
            client  = await http_pool.get_client("nvd")
            headers = {"User-Agent": "SecureLens/3.0", "apiKey": self.nvd_key}

            # Prioritise CVEs that still lack full data; critical/high first
            cves_to_enrich = sorted(
                [(cve_id, data) for cve_id, data in vulns.items()
                 if not data.get('description') or data.get('severity') == 'Unknown' or not data.get('remediation')],
                key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'Unknown': 4}.get(
                    x[1].get('severity', 'Unknown'), 5)
            )[:CONFIG.max_cve_enrichment]

            # Parallel enrichment – 5 concurrent requests (NVD API-key limit)
            sem = asyncio.Semaphore(5 if self.nvd_key else 1)

            async def _enrich_single(cve_id: str):
                async with sem:
                    async with limiter:
                        try:
                            response = await client.get(
                                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                                params={"cveId": cve_id},
                                headers=headers,
                                timeout=20.0,
                            )
                            if response.status_code == 200:
                                cve_items = response.json().get('vulnerabilities', [])
                                if cve_items:
                                    cve_data = cve_items[0].get('cve', {})

                                    # Description
                                    for desc in cve_data.get('descriptions', []):
                                        if desc.get('lang') == 'en':
                                            vulns[cve_id]['description'] = desc.get('value', '')[:500]
                                            break

                                    # CVSS and vector
                                    metrics = cve_data.get('metrics', {})
                                    for ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                                        if ver in metrics and metrics[ver]:
                                            cvss_info    = metrics[ver][0].get('cvssData', {})
                                            exploit_info = metrics[ver][0]
                                            vulns[cve_id]['cvss']               = cvss_info.get('baseScore')
                                            vulns[cve_id]['severity']           = cvss_info.get('baseSeverity', 'Unknown')
                                            vulns[cve_id]['cvss_vector']        = cvss_info.get('vectorString', '')
                                            vulns[cve_id]['attack_vector']      = cvss_info.get('attackVector', '')
                                            vulns[cve_id]['attack_complexity']  = cvss_info.get('attackComplexity', '')
                                            vulns[cve_id]['exploitability_score'] = exploit_info.get('exploitabilityScore')
                                            vulns[cve_id]['impact_score']       = exploit_info.get('impactScore')
                                            break

                                    # Dates
                                    vulns[cve_id]['published']     = cve_data.get('published', '')[:10]
                                    vulns[cve_id]['last_modified']  = cve_data.get('lastModified', '')[:10]

                                    # CWE
                                    cwe_list = []
                                    for weakness in cve_data.get('weaknesses', []):
                                        for cwe_desc in weakness.get('description', []):
                                            if cwe_desc.get('lang') == 'en':
                                                cw = cwe_desc.get('value', '')
                                                if cw and cw != 'NVD-CWE-noinfo':
                                                    cwe_list.append(cw)
                                    vulns[cve_id]['cwe']      = cwe_list[0] if cwe_list else None
                                    vulns[cve_id]['cwe_list'] = cwe_list

                                    # References
                                    patch_refs, advisory_refs = [], []
                                    for ref in cve_data.get('references', [])[:10]:
                                        url  = ref.get('url', '')
                                        tags = ref.get('tags', [])
                                        if 'Patch' in tags:
                                            patch_refs.append(url)
                                        elif 'Vendor Advisory' in tags or 'Third Party Advisory' in tags:
                                            advisory_refs.append(url)
                                    vulns[cve_id]['patch_urls']    = patch_refs[:3]
                                    vulns[cve_id]['advisory_urls'] = advisory_refs[:3]

                                    # Remediation
                                    vulns[cve_id]['remediation'] = self._generate_remediation(vulns[cve_id])
                                    vulns[cve_id]['kev'] = False  # updated by KEV check below

                            await asyncio.sleep(CONFIG.nvd_rate_limit)
                        except Exception as _e:
                            logger.debug(f"CVE enrichment error for {cve_id}: {_e}")

            # Run all enrichment tasks in parallel (semaphore keeps concurrency safe)
            await asyncio.gather(*[_enrich_single(cve_id) for cve_id, _ in cves_to_enrich])

            # Post-enrichment: CISA KEV + EPSS
            await self._check_kev(vulns)
            await self._fetch_epss_scores(vulns)

        except Exception as e:
            logger.debug(f"CVE enrichment error: {e}")
    async def _fetch_epss_scores(self, vulns: dict):
        """Batch-fetch EPSS exploit-probability scores from first.org (free, no key needed).
        Updates each CVE entry with epss (0-1 float) and epss_percentile.
        """
        if not vulns:
            return
        try:
            cve_ids = [cid for cid in vulns if cid.upper().startswith("CVE-")]
            if not cve_ids:
                return
            client = await http_pool.get_client("epss")
            # first.org accepts up to 100 CVE IDs per request as comma-separated query param
            batch_size = 100
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i + batch_size]
                try:
                    response = await client.get(
                        "https://api.first.org/data/v1/epss",
                        params={"cve": ",".join(batch)},
                        timeout=15.0,
                    )
                    if response.status_code == 200:
                        for item in response.json().get("data", []):
                            cid = item.get("cve", "")
                            if cid in vulns:
                                try:
                                    vulns[cid]["epss"] = round(float(item.get("epss", 0)), 6)
                                    vulns[cid]["epss_percentile"] = round(float(item.get("percentile", 0)), 4)
                                except (TypeError, ValueError):
                                    pass
                except Exception as _be:
                    logger.debug(f"EPSS batch error: {_be}")
        except Exception as e:
            logger.debug(f"EPSS fetch error: {e}")
    def _generate_remediation(self, vuln: dict) -> dict:
        """Generate remediation guidance based on CVE details"""
        severity = vuln.get('severity', 'Unknown')
        cvss = vuln.get('cvss') or 0
        cwe = vuln.get('cwe', '')
        tech = vuln.get('technology', '')
        attack_vector = vuln.get('attack_vector', '')
        
        remediation = {
            "priority": "LOW",
            "timeframe": "Within 90 days",
            "actions": [],
            "mitigations": []
        }
        
        # Set priority based on severity
        if severity == 'CRITICAL':
            remediation["priority"] = "CRITICAL"
            remediation["timeframe"] = "Immediate - Within 24 hours"
            remediation["actions"].append("Initiate emergency patching procedure")
            remediation["actions"].append("Consider taking affected systems offline if no patch available")
        elif severity == 'HIGH':
            remediation["priority"] = "HIGH"
            remediation["timeframe"] = "Within 7 days"
            remediation["actions"].append("Schedule priority patching")
            remediation["actions"].append("Implement compensating controls")
        elif severity == 'MEDIUM':
            remediation["priority"] = "MEDIUM"
            remediation["timeframe"] = "Within 30 days"
            remediation["actions"].append("Include in next patch cycle")
        else:
            remediation["priority"] = "LOW"
            remediation["timeframe"] = "Within 90 days"
            remediation["actions"].append("Monitor and patch during regular maintenance")
        
        # Add technology-specific guidance
        if tech:
            tech_lower = tech.lower()
            if 'apache' in tech_lower:
                remediation["actions"].append(f"Update Apache HTTP Server to latest stable version")
                remediation["mitigations"].append("Review Apache security configuration")
            elif 'nginx' in tech_lower:
                remediation["actions"].append("Update Nginx to latest stable version")
                remediation["mitigations"].append("Review Nginx security directives")
            elif 'wordpress' in tech_lower:
                remediation["actions"].append("Update WordPress core, themes, and plugins")
                remediation["mitigations"].append("Enable WordPress auto-updates")
            elif 'php' in tech_lower:
                remediation["actions"].append("Update PHP to latest supported version")
                remediation["mitigations"].append("Review php.ini security settings")
            elif 'mysql' in tech_lower or 'mariadb' in tech_lower:
                remediation["actions"].append("Update MySQL/MariaDB to latest version")
                remediation["mitigations"].append("Restrict database network access")
            elif 'openssl' in tech_lower:
                remediation["actions"].append("Update OpenSSL library immediately")
                remediation["mitigations"].append("Regenerate SSL certificates if compromised")
        
        # Add attack vector specific mitigations
        if attack_vector == 'NETWORK':
            remediation["mitigations"].append("Implement network segmentation")
            remediation["mitigations"].append("Review firewall rules")
        elif attack_vector == 'ADJACENT_NETWORK':
            remediation["mitigations"].append("Isolate affected systems on separate VLAN")
        
        # Add CWE-specific guidance
        if cwe:
            cwe_guidance = {
                'CWE-79': "Implement input validation and output encoding (XSS)",
                'CWE-89': "Use parameterized queries to prevent SQL injection",
                'CWE-22': "Validate and sanitize file paths (Path Traversal)",
                'CWE-78': "Avoid shell command execution with user input (OS Command Injection)",
                'CWE-352': "Implement CSRF tokens on all forms",
                'CWE-287': "Review and strengthen authentication mechanisms",
                'CWE-502': "Avoid deserializing untrusted data",
                'CWE-918': "Validate and whitelist URLs for SSRF prevention",
                'CWE-434': "Implement strict file upload validation",
                'CWE-611': "Disable external entity processing in XML parsers (XXE)",
            }
            for cwe_id, guidance in cwe_guidance.items():
                if cwe_id in cwe:
                    remediation["mitigations"].append(guidance)
        
        # Add patch URLs if available
        if vuln.get('patch_urls'):
            remediation["actions"].append("Apply vendor patch from provided URL")
        
        return remediation
    
    async def _check_kev(self, vulns: dict):
        """Check CVEs against CISA Known Exploited Vulnerabilities catalog"""
        try:
            client = await http_pool.get_client("kev")
            response = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=15.0
            )
            if response.status_code == 200:
                kev_data = response.json()
                kev_cves = {v.get('cveID'): v for v in kev_data.get('vulnerabilities', [])}
                
                for cve_id in vulns:
                    if cve_id in kev_cves:
                        vulns[cve_id]['kev'] = True
                        vulns[cve_id]['kev_date_added'] = kev_cves[cve_id].get('dateAdded')
                        vulns[cve_id]['kev_due_date'] = kev_cves[cve_id].get('dueDate')
                        vulns[cve_id]['kev_required_action'] = kev_cves[cve_id].get('requiredAction')
                        
                        # Bump priority if in KEV
                        if vulns[cve_id].get('remediation'):
                            vulns[cve_id]['remediation']['priority'] = 'CRITICAL'
                            vulns[cve_id]['remediation']['timeframe'] = 'Immediate - Known exploited in the wild'
                            vulns[cve_id]['remediation']['actions'].insert(0, "⚠️ CISA KEV: Known to be exploited in the wild")
        except Exception as e:
            logger.debug(f"KEV check error: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# Analysis Engine - Main orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class AnalysisEngine:
    """Main analysis orchestrator with staged batching and weighted risk scoring"""
    
    RISK_WEIGHTS = {
        "VirusTotal": 1.5,
        "AbuseIPDB": 1.3,
        "URLScan": 1.3,
        "CVEAnalysis": 1.2,
        "DeepContent": 1.0,
        "SSLCheck": 0.8,
        "WHOIS": 0.7,
    }

    BATCH_PLAN = (
        {"name": "foundation", "concurrency": 3, "scanners": ["DeepContent", "DNS", "SSLCheck", "WHOIS", "TechStack", "GeoIP"]},
        {"name": "reputation", "concurrency": 3, "scanners": ["VirusTotal", "AbuseIPDB", "URLScan"]},
        {"name": "infrastructure", "concurrency": 2, "scanners": ["Shodan", "SubdomainDiscovery", "SecurityTrails", "Chaos"]},
        {"name": "vulnerability", "concurrency": 2, "scanners": ["NVD", "CVEAnalysis"]},
    )

    RESULT_DEFAULTS = {
        "VirusTotal": {
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_engines": 0,
            "detection_ratio": "0/0",
            "malicious_engines": [],
            "categories": {},
        },
        "AbuseIPDB": {"score": 0, "totalReports": 0, "numDistinctUsers": 0},
        "URLScan": {"uuid": None, "report_url": None, "screenshot_url": None, "malicious": False, "score": 0, "brands": [], "categories": []},
        "Shodan": {"ports": [], "services": [], "vulns": [], "vulns_count": 0, "exposed_risky_ports": []},
        "SubdomainDiscovery": {"subdomains": [], "valid_subdomains": [], "sources": {}},
        "SecurityTrails": {"subdomains": []},
        "Chaos": {"subdomains": []},
        "NVD": {"vulnerabilities": [], "total_found": 0, "critical_count": 0, "high_count": 0, "detected_techs": [], "search_terms": []},
        "CVEAnalysis": {"vulnerabilities": [], "scanned_ips": [], "ip_details": {}, "scanned_subdomains": [], "cve_sources": {}},
    }

    REQUIRED_FIELDS = {
        "VirusTotal": ("malicious_count", "suspicious_count", "harmless_count", "total_engines"),
        "AbuseIPDB": ("score",),
        "URLScan": ("score", "categories"),
        "Shodan": ("ports", "services", "vulns"),
        "SubdomainDiscovery": ("subdomains", "valid_subdomains"),
        "SecurityTrails": ("subdomains",),
        "Chaos": ("subdomains",),
        "NVD": ("vulnerabilities", "search_terms"),
        "CVEAnalysis": ("vulnerabilities", "scanned_subdomains", "ip_details"),
    }

    TOLERANT_STATUS_KEYWORDS = (
        "error",
        "timeout",
        "failed",
        "no api key",
        "no ip",
        "no hostname",
        "could not resolve ip",
        "not found",
        "not indexed",
        "invalid",
        "lookup failed",
        "domain not indexed",
    )
    
    def __init__(self, db):
        self.db = db
        
        # Load API keys from database first, fallback to config
        self.keys = {
            "vt": db.get_config_value('VIRUSTOTAL_API_KEY') or CONFIG.virustotal_key,
            "shodan": db.get_config_value('SHODAN_API_KEY') or CONFIG.shodan_key,
            "ipinfo": db.get_config_value('IPINFO_TOKEN') or CONFIG.ipinfo_token,
            "abuse": db.get_config_value('ABUSEIPDB_API_KEY') or CONFIG.abuseipdb_key,
            "urlscan": db.get_config_value('URLSCAN_API_KEY') or CONFIG.urlscan_key,
            "securitytrails": db.get_config_value('SECURITYTRAILS_API_KEY') or CONFIG.securitytrails_key,
            "chaos": db.get_config_value('CHAOS_API_KEY') or CONFIG.chaos_key,
            "nvd": db.get_config_value('NVD_API_KEY') or CONFIG.nvd_key,
        }
        
        # Initialize scanners
        self.scanners = [
            # Content analysis
            DeepContentScanner(),
            
            # Reputation services
            VirusTotalScanner(self.keys['vt']),
            AbuseIPDBScanner(self.keys['abuse']),
            URLScanScanner(self.keys['urlscan']),
            
            # Infrastructure
            ShodanScanner(self.keys['shodan']),
            GeoScanner(self.keys['ipinfo']),
            SSLScanner(),
            
            # Information gathering
            TechStackScanner(),
            WhoisScanner(),
            DNSScanner(),
            
            # Subdomain discovery
            SubdomainDiscoveryScanner(),
            SecurityTrailsScanner(self.keys['securitytrails']),
            ChaosScanner(self.keys['chaos']),
            
            # Vulnerability scanning
            NVDScanner(self.keys['nvd']),
            ComprehensiveCVEScanner(self.keys['shodan'], self.keys['nvd']),
        ]
        self.scanner_map = {scanner.name: scanner for scanner in self.scanners}
        
        logger.info(f"AnalysisEngine initialized with {len(self.scanners)} scanners")
    
    async def analyze_url(self, url: str, progress_callback=None) -> dict:
        """Execute comprehensive URL analysis"""
        
        # Clear caches
        NetworkUtils.clear_cache()
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        host = NetworkUtils.get_hostname(url)
        
        # Check governance rules
        for rule in self.db.get_rules():
            if self._rule_matches_host(host, rule.get('domain', '')):
                if rule['rule_type'] == 'WHITELIST':
                    return self._whitelist_response(url, rule['domain'])
                elif rule['rule_type'] == 'BLACKLIST':
                    return self._blacklist_response(url, rule['domain'])
        
        # Execute scanners in staged batches so external providers are processed in
        # a controlled queue instead of all faning out at once.
        results_list, execution_flow = await self._execute_batched_pipeline(url, progress_callback=progress_callback)
        
        # Process results
        results = {}
        risk_scores = []
        deep_data = {}
        
        for res in results_list:
            if isinstance(res, Exception):
                logger.error(f"Scanner error: {res}")
                continue
            
            if isinstance(res, dict) and 'source' in res:
                source = res['source']
                public_result = {k: v for k, v in res.items() if not str(k).startswith("_batch_")}
                results[source] = public_result
                
                base_risk = public_result.get('risk_contribution', 0)
                # CVE scanners and Shodan are informational only - exclude from risk calculation
                if base_risk > 0 and source not in ('NVD', 'CVEAnalysis', 'Shodan'):
                    weight = self.RISK_WEIGHTS.get(source, 1.0)
                    risk_scores.append((source, base_risk, base_risk * weight))
                
                if source == "DeepContent":
                    deep_data = public_result

        # ── Merge all CVE sources into the unified CVEAnalysis.vulnerabilities list ──
        # This ensures every CVE from NVD (standalone) and Shodan (standalone) also
        # appears in the Vulnerabilities tab in the UI, not just in their own sections.
        cva = results.get("CVEAnalysis", {})
        cva_vulns: list = cva.get("vulnerabilities", [])
        cva_seen: set = {v.get("id") for v in cva_vulns if v.get("id")}

        # Merge NVD standalone results
        nvd_res = results.get("NVD", {})
        for v in nvd_res.get("vulnerabilities", []):
            cid = v.get("id")
            if cid and cid not in cva_seen:
                cva_vulns.append(v)
                cva_seen.add(cid)

        # Merge Shodan standalone CVE IDs (top-level list, may lack detail)
        shodan_res = results.get("Shodan", {})
        shodan_vulns_raw = shodan_res.get("vulns", [])
        if isinstance(shodan_vulns_raw, list):
            for cid in shodan_vulns_raw:
                if cid and cid not in cva_seen:
                    cva_vulns.append({
                        "id": cid,
                        "severity": "Unknown",
                        "cvss": None,
                        "description": "",
                        "source": "Shodan",
                    })
                    cva_seen.add(cid)

        # Write merged list back
        if cva_vulns:
            if "CVEAnalysis" not in results:
                results["CVEAnalysis"] = {
                    "source": "CVEAnalysis",
                    "status": "success",
                    "risk_contribution": 0,
                }
            results["CVEAnalysis"]["vulnerabilities"] = cva_vulns
            results["CVEAnalysis"]["total_vulnerabilities"] = len(cva_vulns)
        
        # Calculate final risk
        final_risk = 0
        if risk_scores:
            max_weighted = max(score[2] for score in risk_scores)
            avg_weighted = sum(score[2] for score in risk_scores) / len(risk_scores)
            final_risk = int(min((max_weighted * 0.7 + avg_weighted * 0.3), 100))
        
        # Determine verdict
        if final_risk >= 75:
            verdict = "MALICIOUS"
        elif final_risk >= 50:
            verdict = "SUSPICIOUS"
        elif final_risk >= 25:
            verdict = "CAUTION"
        else:
            verdict = "SAFE"
        
        risk_breakdown = [
            {"source": s, "base_risk": br, "weighted_risk": round(wr, 1)}
            for s, br, wr in sorted(risk_scores, key=lambda x: x[2], reverse=True)
        ]
        
        return {
            "target_url": url,
            "verdict": verdict,
            "risk_score": final_risk,
            "risk_breakdown": risk_breakdown,
            "details": results,
            "redirect_chain": deep_data.get('redirect_chain', []),
            "http_headers": deep_data.get('http_headers', {}),
            "page_meta": deep_data.get('page_meta', {"title": "Unknown"}),
            "dom_stats": deep_data.get('dom_stats', {}),
            "server_info": deep_data.get('server_info', {}),
            "security_headers": deep_data.get('security_headers', {}),
            "security_headers_score": deep_data.get('security_headers_score', 0),
            "execution_flow": execution_flow,
        }

    async def _execute_batched_pipeline(self, url: str, progress_callback=None) -> Tuple[List[dict], List[dict]]:
        """Run scanner groups sequentially with bounded per-batch concurrency."""
        results: List[dict] = []
        execution_flow: List[dict] = []
        total_batches = max(1, len(self.BATCH_PLAN))

        for index, batch in enumerate(self.BATCH_PLAN, start=1):
            if progress_callback:
                stage_name, step_number = self._progress_stage_for_batch(batch["name"])
                await progress_callback(
                    stage_name,
                    step_number,
                    self._progress_message_for_batch(batch["name"]),
                    self._progress_percent_for_batch(index, total_batches),
                )
            batch_results = await self._execute_scanner_batch(url, batch)
            results.extend(batch_results)

            incomplete = [result["source"] for result in batch_results if not result.get("_batch_complete", True)]
            execution_flow.append({
                "batch": batch["name"],
                "scanner_count": len(batch_results),
                "completed": len(batch_results) - len(incomplete),
                "incomplete": incomplete,
            })

            if incomplete:
                logger.warning(
                    "Batch '%s' completed with incomplete scanner payloads: %s",
                    batch["name"],
                    ", ".join(incomplete),
                )

        return results, execution_flow

    async def _execute_scanner_batch(self, url: str, batch: Dict[str, Any]) -> List[dict]:
        scanner_names = [name for name in batch.get("scanners", []) if name in self.scanner_map]
        coroutines = [self._run_scanner_once(self.scanner_map[name], url) for name in scanner_names]
        raw_results = await gather_in_batches(coroutines, batch.get("concurrency", 1), return_exceptions=False)

        validated_results: List[Optional[dict]] = [None] * len(raw_results)
        retry_targets: List[Tuple[int, str]] = []

        for index, raw_result in enumerate(raw_results):
            normalized, complete, missing_fields = self._normalize_scanner_result(raw_result)
            normalized["_batch_complete"] = complete
            if missing_fields:
                normalized["_batch_missing_fields"] = missing_fields
            validated_results[index] = normalized

            if not complete:
                retry_targets.append((index, normalized["source"]))

        if retry_targets:
            retry_coroutines = [
                self._run_scanner_once(self.scanner_map[source], url)
                for _, source in retry_targets
            ]
            retry_results = await gather_in_batches(
                retry_coroutines,
                batch.get("concurrency", 1),
                return_exceptions=False,
            )

            for (index, _source), retry_result in zip(retry_targets, retry_results):
                normalized, complete, missing_fields = self._normalize_scanner_result(retry_result)
                if not complete:
                    logger.warning(
                        "Scanner '%s' remained incomplete after retry. Missing fields: %s",
                        normalized["source"],
                        ", ".join(missing_fields),
                    )

                normalized["_batch_complete"] = complete
                if missing_fields:
                    normalized["_batch_missing_fields"] = missing_fields
                validated_results[index] = normalized

        return [result for result in validated_results if result is not None]

    async def _run_scanner_once(self, scanner: AsyncScannerStrategy, url: str) -> dict:
        try:
            result = await scanner.scan(url)
            if isinstance(result, dict):
                return result
            return {
                "source": scanner.name,
                "status": "Error",
                "error": "Scanner returned a non-dict payload",
                "risk_contribution": 0,
            }
        except Exception as exc:
            logger.error("Scanner '%s' raised an exception: %s", scanner.name, exc)
            return {
                "source": scanner.name,
                "status": "Error",
                "error": str(exc),
                "risk_contribution": 0,
            }

    def _normalize_scanner_result(self, result: dict) -> Tuple[dict, bool, List[str]]:
        source = result.get("source") or "Unknown"
        normalized = {
            "source": source,
            "status": result.get("status", "Unknown"),
            "risk_contribution": result.get("risk_contribution", 0),
            **{k: v for k, v in result.items() if k not in {"source", "status", "risk_contribution"}},
        }

        for key, default_value in self.RESULT_DEFAULTS.get(source, {}).items():
            normalized.setdefault(key, default_value)

        status_text = str(normalized.get("status", "")).lower()
        is_tolerant_status = any(keyword in status_text for keyword in self.TOLERANT_STATUS_KEYWORDS)
        missing_fields = [
            field for field in self.REQUIRED_FIELDS.get(source, ())
            if normalized.get(field) is None
        ]

        return normalized, (is_tolerant_status or not missing_fields), missing_fields

    def _progress_stage_for_batch(self, batch_name: str) -> Tuple[str, int]:
        if batch_name == "foundation":
            return "fetching", 1
        if batch_name == "reputation":
            return "scanning", 2
        if batch_name == "infrastructure":
            return "scanning", 2
        if batch_name == "vulnerability":
            return "ai_analysis", 3
        return "fetching", 1

    def _progress_message_for_batch(self, batch_name: str) -> str:
        messages = {
            "foundation": "Collecting page signals, DNS records, and certificate details...",
            "reputation": "Checking reputation sources such as VirusTotal and abuse databases...",
            "infrastructure": "Inspecting infrastructure exposure, assets, and discovered subdomains...",
            "vulnerability": "Correlating vulnerabilities and preparing the risk analysis...",
        }
        return messages.get(batch_name, "Running analysis...")

    def _progress_percent_for_batch(self, index: int, total_batches: int) -> int:
        milestones = [12, 42, 68, 84]
        if 1 <= index <= len(milestones):
            return milestones[index - 1]
        return min(84, max(8, int((index / max(total_batches, 1)) * 84)))
    
    def _whitelist_response(self, url: str, domain: str) -> dict:
        return {
            "target_url": url, "verdict": "SAFE", "risk_score": 0,
            "details": {"Governance": {"status": "Whitelisted", "domain": domain}},
            "redirect_chain": [], "http_headers": {},
            "page_meta": {"title": "Whitelisted Domain"},
            "dom_stats": {}, "server_info": {}
        }
    
    def _blacklist_response(self, url: str, domain: str) -> dict:
        return {
            "target_url": url, "verdict": "MALICIOUS", "risk_score": 100,
            "details": {"Governance": {"status": "Blacklisted", "domain": domain}},
            "redirect_chain": [], "http_headers": {},
            "page_meta": {"title": "Blacklisted Domain"},
            "dom_stats": {}, "server_info": {}
        }

    def _rule_matches_host(self, host: Optional[str], rule_domain: str) -> bool:
        """Match exact domains and subdomains without unsafe substring checks."""
        normalized_host = (host or "").strip().lower()
        normalized_rule = (rule_domain or "").strip().lower()

        if not normalized_host or not normalized_rule:
            return False

        return (
            normalized_host == normalized_rule
            or normalized_host.endswith(f".{normalized_rule}")
        )
    
    async def cleanup(self):
        """Cleanup resources"""
        await http_pool.close_all()
