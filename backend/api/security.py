"""
api/security.py: protections needed once the API is reachable from the internet.

- validate_target(): only http(s) URLs whose host resolves to PUBLIC addresses.
  Without this, anyone could point the sandbox browser at the container's own
  Redis (127.0.0.1:6379) or a cloud metadata endpoint (SSRF). sandbox/run.py
  re-checks every request the page makes, which covers redirects.
  Known gap: DNS rebinding between this check and the browser's own lookup.
- check_basic(): optional shared password (HTTP Basic). Enabled when
  BASIC_AUTH_PASSWORD is set; the browser shows its native login prompt.
"""
import base64
import hmac
import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048


def _host_is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # unresolvable: nothing internal to reach, the sandbox will report it
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return False
    return True


def validate_target(target: str) -> str:
    """Return a normalized URL, or raise ValueError with a user-facing reason."""
    url = target.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL is too long")
    if "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        parsed.port  # raises ValueError on a malformed port, e.g. "javascript:alert(1)"
    except ValueError:
        raise ValueError("That doesn’t look like a valid URL")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs can be analyzed")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    if not _host_is_public(parsed.hostname):
        raise ValueError("That address is private or internal and can’t be analyzed")
    return url


def auth_enabled() -> bool:
    return bool(os.getenv("BASIC_AUTH_PASSWORD"))


def check_basic(authorization: Optional[str]) -> bool:
    if not auth_enabled():
        return True
    if not authorization or not authorization.lower().startswith("basic "):
        return False
    try:
        user, _, password = base64.b64decode(authorization[6:]).decode().partition(":")
    except Exception:
        return False
    ok_user = hmac.compare_digest(user.encode(), os.getenv("BASIC_AUTH_USER", "admin").encode())
    ok_pass = hmac.compare_digest(password.encode(), os.getenv("BASIC_AUTH_PASSWORD", "").encode())
    return ok_user and ok_pass
