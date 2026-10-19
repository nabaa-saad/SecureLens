"""
Domain and URL canonicalization helpers.

This module centralizes registrable-domain extraction so scan caching and
extension behavior consistently operate on the main domain rather than an
arbitrary subdomain.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class CanonicalTarget:
    """Normalized scan target details."""

    raw_input: str
    normalized_url: str
    hostname: str
    canonical_domain: str
    scan_url: str


def extract_hostname(raw_value: str) -> str:
    """Extract a lowercase hostname from a URL or hostname string."""
    candidate = (raw_value or "").strip()
    if not candidate:
        return ""

    if "://" not in candidate:
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    return hostname


def is_ip_address(value: str) -> bool:
    """Return True when the value is an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


@lru_cache(maxsize=1)
def _load_public_suffix_rules() -> tuple[set[str], set[str], set[str]]:
    """Load public suffix rules from the bundled whois PSL file when present."""
    exact_rules: set[str] = set()
    wildcard_rules: set[str] = set()
    exception_rules: set[str] = set()

    try:
        data_root = resources.files("whois").joinpath("data", "public_suffix_list.dat")
        with data_root.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("//"):
                    continue
                if line.startswith("!."):
                    # Defensive fallback for malformed data; treat like exception.
                    line = f"!{line[2:]}"
                if line.startswith("!"):
                    exception_rules.add(line[1:])
                elif line.startswith("*."):
                    wildcard_rules.add(line[2:])
                else:
                    exact_rules.add(line)
    except Exception:
        # Fallback to a small heuristic set when the PSL resource is unavailable.
        exact_rules.update({"com", "org", "net", "edu", "gov", "co.uk", "edu.iq"})

    return exact_rules, wildcard_rules, exception_rules


def get_public_suffix(hostname: str) -> str:
    """Return the public suffix for a hostname."""
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if is_ip_address(host):
        return host

    labels = [label for label in host.split(".") if label]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]

    exact_rules, wildcard_rules, exception_rules = _load_public_suffix_rules()

    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in exception_rules:
            return ".".join(candidate.split(".")[1:])

    best_match = labels[-1]
    best_size = 1

    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        match_size = len(labels) - index

        if candidate in exact_rules and match_size > best_size:
            best_match = candidate
            best_size = match_size

        if index + 1 < len(labels):
            wildcard_suffix = ".".join(labels[index + 1 :])
            if wildcard_suffix in wildcard_rules and match_size > best_size:
                best_match = candidate
                best_size = match_size

    return best_match


def get_registrable_domain(hostname: str) -> str:
    """Return the registrable domain (eTLD+1) for a hostname."""
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if is_ip_address(host) or host == "localhost":
        return host

    labels = [label for label in host.split(".") if label]
    if len(labels) <= 1:
        return host

    public_suffix = get_public_suffix(host)
    suffix_labels = [label for label in public_suffix.split(".") if label]
    if not suffix_labels:
        return host

    if len(labels) <= len(suffix_labels):
        return host

    return ".".join(labels[-(len(suffix_labels) + 1) :])


def build_scan_url(canonical_domain: str, preferred_scheme: str = "https") -> str:
    """Build a canonical scan URL for a registrable domain."""
    domain = (canonical_domain or "").strip().lower()
    if not domain:
        return ""

    scheme = preferred_scheme if preferred_scheme in {"http", "https"} else "https"
    if is_ip_address(domain) or domain == "localhost":
        scheme = "http"

    return f"{scheme}://{domain}"


def canonicalize_target(raw_value: str, preferred_scheme: str = "https") -> CanonicalTarget:
    """Normalize raw user input into a canonical domain scan target."""
    candidate = (raw_value or "").strip()
    if not candidate:
        raise ValueError("A URL or domain is required")

    normalized_url = candidate
    if "://" not in normalized_url:
        normalized_url = f"http://{normalized_url}"

    parsed = urlparse(normalized_url)
    hostname = extract_hostname(normalized_url)
    if not hostname:
        raise ValueError("Please enter a valid URL or domain")

    canonical_domain = get_registrable_domain(hostname)
    scan_url = build_scan_url(canonical_domain, parsed.scheme or preferred_scheme)

    return CanonicalTarget(
        raw_input=candidate,
        normalized_url=normalized_url,
        hostname=hostname,
        canonical_domain=canonical_domain,
        scan_url=scan_url,
    )


def get_base_domain(hostname: str) -> str:
    """Compatibility wrapper for existing call sites."""
    return get_registrable_domain(hostname)

