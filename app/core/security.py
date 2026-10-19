"""
Security utilities - password hashing, JWT token management, CSRF protection, and rate limiting
"""

import os
import re
import hmac
import hashlib
import secrets
import configparser
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid4

import bcrypt
from jose import JWTError, jwt


# ─── Secret Key Management ────────────────────────────────────────────────────
def _load_secret_key() -> str:
    """Load SECRET_KEY from environment, config.ini, or auto-generate one."""
    # 1. Environment variable (highest priority)
    env_key = os.getenv("SECRET_KEY", "").strip()
    if env_key and env_key != "your-secret-key-change-it-in-production":
        return env_key
    
    # 2. config.ini [SYSTEM] section
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config.ini')
    config_path = os.path.abspath(config_path)
    config = configparser.ConfigParser()
    
    if os.path.exists(config_path):
        config.read(config_path)
        ini_key = config.get('SYSTEM', 'SECRET_KEY', fallback='').strip()
        if ini_key and ini_key != "your-secret-key-change-it-in-production":
            return ini_key
    
    # 3. Auto-generate and append to config.ini [SYSTEM] section
    generated_key = secrets.token_hex(32)
    try:
        # Read existing file content and append SECRET_KEY to [SYSTEM] section
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Insert SECRET_KEY after [SYSTEM] section header
        if '[SYSTEM]' in content:
            content = content.replace(
                '[SYSTEM]\n',
                f'[SYSTEM]\nSECRET_KEY = {generated_key}\n',
                1
            )
        else:
            content += f'\n[SYSTEM]\nSECRET_KEY = {generated_key}\n'
        
        with open(config_path, 'w') as f:
            f.write(content)
        
        print(f"\u26a0\ufe0f  AUTO-GENERATED SECRET_KEY and saved to config.ini. Keep this file secure!")
    except Exception as e:
        print(f"\u26a0\ufe0f  AUTO-GENERATED SECRET_KEY (could not persist to config.ini: {e})")
    
    return generated_key


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ─── Password Hashing ─────────────────────────────────────────────────────────
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain text password against the stored hash."""
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


# ─── Password Policy ──────────────────────────────────────────────────────────
def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password meets security requirements.
    Returns (is_valid, error_message).
    Requirements: min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character"
    return True, ""


def generate_random_token(length: int = 32) -> str:
    """Generate a URL-safe random token."""
    return secrets.token_urlsafe(length)


def hash_token_value(token: str) -> str:
    """Hash tokens before storing them in the database."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


# ─── JWT Token Management ─────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a JWT access token with a unique JTI (JWT ID) for blacklisting support."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "jti": str(uuid4()),
        "iat": datetime.utcnow(),
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    """Decode a JWT token. Returns full payload dict with 'sub', 'jti', etc. or None."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ─── CSRF Protection ──────────────────────────────────────────────────────────
def generate_csrf_token(session_id: str = "") -> str:
    """Generate a CSRF token tied to a session identifier."""
    nonce = secrets.token_hex(16)
    message = f"{nonce}:{session_id}".encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return f"{nonce}:{signature}"


def validate_csrf_token(token: str, session_id: str = "") -> bool:
    """Validate a CSRF token against the session identifier."""
    if not token or ':' not in token:
        return False
    try:
        nonce, provided_sig = token.split(':', 1)
        message = f"{nonce}:{session_id}".encode('utf-8')
        expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided_sig, expected_sig)
    except Exception:
        return False


# ─── IP-based Rate Limiting ───────────────────────────────────────────────────
class RateLimiter:
    """In-memory IP-based rate limiter for login attempts."""
    
    def __init__(self, max_attempts: int = 10, window_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict = defaultdict(list)
    
    def is_rate_limited(self, ip: str) -> bool:
        """Check if an IP has exceeded the rate limit."""
        self._cleanup(ip)
        return len(self._attempts[ip]) >= self.max_attempts
    
    def record_attempt(self, ip: str):
        """Record a login attempt from an IP."""
        self._cleanup(ip)
        self._attempts[ip].append(datetime.utcnow())
    
    def get_remaining_time(self, ip: str) -> int:
        """Get seconds until the oldest attempt expires from the window."""
        self._cleanup(ip)
        if not self._attempts[ip]:
            return 0
        oldest = self._attempts[ip][0]
        expires_at = oldest + timedelta(seconds=self.window_seconds)
        remaining = (expires_at - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))
    
    def _cleanup(self, ip: str):
        """Remove expired attempts."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]


# Global rate limiter instance: 10 attempts per 15 minutes
login_rate_limiter = RateLimiter(max_attempts=10, window_seconds=900)


# ─── Scan Rate Limiting (Guest) ───────────────────────────────────────────────

class ScanRateLimiter:
    """In-memory IP-based rate limiter for guest scan attempts."""

    def __init__(self, max_scans: int = 5, window_seconds: int = 3600):
        self.max_scans = max_scans
        self.window_seconds = window_seconds
        self._scans: dict = defaultdict(list)

    def is_scan_limited(self, ip: str) -> bool:
        """Check if an IP has exceeded the scan rate limit."""
        self._cleanup(ip)
        return len(self._scans[ip]) >= self.max_scans

    def record_scan(self, ip: str):
        """Record a scan attempt from an IP."""
        self._cleanup(ip)
        self._scans[ip].append(datetime.utcnow())

    def get_remaining_time(self, ip: str) -> int:
        """Get seconds until the oldest scan expires from the window."""
        self._cleanup(ip)
        if not self._scans[ip]:
            return 0
        oldest = self._scans[ip][0]
        expires_at = oldest + timedelta(seconds=self.window_seconds)
        remaining = (expires_at - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))

    def get_scan_count(self, ip: str) -> int:
        """Get the number of scans in the current window."""
        self._cleanup(ip)
        return len(self._scans[ip])

    def _cleanup(self, ip: str):
        """Remove expired scan records."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        self._scans[ip] = [t for t in self._scans[ip] if t > cutoff]


# Global scan rate limiter: 5 scans per hour for guests
scan_rate_limiter = ScanRateLimiter(max_scans=5, window_seconds=3600)


# ─── Scan Pattern Tracker ─────────────────────────────────────────────────────

class ScanPatternTracker:
    """Detect suspicious scanning patterns per IP address.

    Tracks (timestamp, url) tuples in a 1-hour sliding window and flags:
      - rapid_fire:    >10 scans in 5 minutes
      - domain_sweep:  >5 unique domains in 10 minutes
      - repeat_target: same URL scanned >3 times in 30 minutes
    """

    def __init__(self):
        # ip -> list of (datetime, url)
        self._history: dict = defaultdict(list)

    def record_and_check(self, ip: str, url: str) -> Optional[str]:
        """Record a scan and return a pattern type if suspicious, else None."""
        now = datetime.utcnow()
        self._cleanup(ip)
        self._history[ip].append((now, url))

        entries = self._history[ip]

        # 1. Rapid fire: >10 scans in 5 minutes
        five_min_ago = now - timedelta(minutes=5)
        recent_5m = [e for e in entries if e[0] > five_min_ago]
        if len(recent_5m) > 10:
            return "rapid_fire"

        # 2. Domain sweep: >5 unique domains in 10 minutes
        ten_min_ago = now - timedelta(minutes=10)
        recent_10m = [e for e in entries if e[0] > ten_min_ago]
        domains = set()
        for _, u in recent_10m:
            try:
                from urllib.parse import urlparse
                domain = urlparse(u).netloc or u
                # Strip port and www prefix for better grouping
                domain = domain.split(":")[0].removeprefix("www.")
                domains.add(domain)
            except Exception:
                domains.add(u)
        if len(domains) > 5:
            return "domain_sweep"

        # 3. Repeat target: same URL >3 times in 30 minutes
        thirty_min_ago = now - timedelta(minutes=30)
        recent_30m = [e for e in entries if e[0] > thirty_min_ago]
        url_count = sum(1 for _, u in recent_30m if u == url)
        if url_count > 3:
            return "repeat_target"

        return None

    def get_scan_count(self, ip: str) -> int:
        """Get total tracked scans for this IP in the window."""
        self._cleanup(ip)
        return len(self._history[ip])

    def get_urls_scanned(self, ip: str) -> list:
        """Get all URLs scanned by this IP in the current window."""
        self._cleanup(ip)
        return [url for _, url in self._history[ip]]

    def _cleanup(self, ip: str):
        """Remove entries older than 1 hour."""
        cutoff = datetime.utcnow() - timedelta(hours=1)
        self._history[ip] = [(t, u) for t, u in self._history[ip] if t > cutoff]


# Global scan pattern tracker instance
scan_pattern_tracker = ScanPatternTracker()
