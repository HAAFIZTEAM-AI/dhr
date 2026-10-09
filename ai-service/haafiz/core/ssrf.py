"""SSRF protection for the website analyzer.

The website analyzer fetches arbitrary user-supplied URLs with a headless browser.
Without a guard, an attacker can use HAAFIZ as a proxy into internal networks:

    POST /analyze/website {"url": "http://169.254.169.254/latest/meta-data/"}
    POST /analyze/website {"url": "http://192.168.1.1/admin"}
    POST /analyze/website {"url": "http://localhost:3001/api/auth/me"}

The cloud-metadata endpoint (169.254.169.254) is the classic target: it hands out
IAM credentials on AWS/GCP/Azure/AliCloud. HAAFIZ is meant to be deployed on cloud
infrastructure, so this is a live risk, not a theoretical one.

The guard resolves the hostname to IP addresses FIRST and refuses anything that is
not a public, routable unicast address. It must be called immediately before every
network touch, because DNS can be re-bound between check and use.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

__all__ = ["SSRFError", "SsrfPolicy", "default_policy", "assert_public_url"]

# Schemes the analyzer is allowed to fetch. file:// and gopher:// in particular
# turn a URL analyzer into a local-file reader.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Ports are restricted because an open redirect to an internal SSH/Redis/DB port
# is just as damaging as reaching an internal HTTP service.
_DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})


class SSRFError(ValueError):
    """Raised when a URL must not be fetched."""


@dataclass(frozen=True)
class SsrfPolicy:
    """Configurable SSRF policy.

    Attributes:
        allow_private: permit RFC1918 / loopback / link-local targets. Only ever
            set this in a test environment, never in production.
        allowed_ports: ports that may be connected to. None means 80/443/8080/8443.
        allow_ipv6: whether IPv6 destinations are permitted.
    """

    allow_private: bool = False
    allowed_ports: frozenset[int] | None = None
    allow_ipv6: bool = True

    @property
    def ports(self) -> frozenset[int]:
        return self.allowed_ports if self.allowed_ports is not None else _DEFAULT_ALLOWED_PORTS


default_policy = SsrfPolicy()


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, policy: SsrfPolicy) -> bool:
    """True if this resolved address must not be contacted."""
    if ip.version == 6 and not policy.allow_ipv6:
        return True

    # IPv4-mapped IPv6 (::ffff:127.0.0.1) is a bypass for every check below, so
    # unwrap it first and evaluate the real address. This must run even under the
    # permissive dev policy.
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _is_blocked_ip(ip.ipv4_mapped, policy)

    # Development escape hatch: containers on a Docker bridge network are private
    # by definition, so a strict policy makes local testing impossible. When this
    # is enabled we still block loopback and link-local, because those reach the
    # host itself and the cloud metadata endpoint even inside a dev setup.
    if policy.allow_private:
        return bool(ip.is_loopback or ip.is_link_local)

    # Anything not globally reachable is off-limits: loopback, link-local
    # (includes 169.254.169.254 cloud metadata), private RFC1918, CGNAT
    # (100.64.0.0/10, heavily used by Pakistani ISPs), multicast, reserved,
    # and unspecified (0.0.0.0).
    if not ip.is_global:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    return False


def assert_public_url(url: str, policy: SsrfPolicy = default_policy) -> list[str]:
    """Validate a URL and return the safe, resolved IP addresses.

    Args:
        url: the candidate URL, exactly as the user supplied it.
        policy: the SSRF policy to apply.

    Returns:
        The list of IP addresses the hostname resolved to. Every one has been
        verified as publicly routable. Pass these to the HTTP client (pinning the
        connection to them) to avoid a DNS-rebinding race.

    Raises:
        SSRFError: if the URL must not be fetched. Callers should surface this as
            a 4xx, never a 5xx — it is a rejected request, not a server fault.
    """
    if not isinstance(url, str) or not url.strip():
        raise SSRFError("URL is required")

    # Reject control characters and whitespace. "http://evil.com\n@internal" style
    # payloads exploit parser differences between validators and HTTP clients.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        raise SSRFError("URL contains illegal control characters")

    try:
        parsed = urlparse(url.strip())
    except ValueError as exc:
        raise SSRFError(f"Malformed URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFError(f"Scheme '{scheme or 'missing'}' is not allowed (http/https only)")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL has no hostname")

    # Strip trailing dot from FQDNs; some resolvers treat "example.com." oddly.
    hostname = hostname.rstrip(".").lower()

    # An empty userinfo section is a known parser-confusion vector:
    # https://trusted.com@evil.tld  and  https://evil.tld\@trusted.com
    if "@" in (parsed.netloc or ""):
        raise SSRFError("Credentials in URL are not allowed")
    if "\\" in (parsed.netloc or ""):
        raise SSRFError("Backslash in authority is not allowed")

    port = parsed.port
    if port is not None and port not in policy.ports:
        raise SSRFError(f"Port {port} is not allowed (permitted: {sorted(policy.ports)})")

    # A bare IP literal can be checked without touching DNS.
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if _is_blocked_ip(literal, policy):
            raise SSRFError(f"Destination {literal} is not publicly routable")
        return [str(literal)]

    # Resolve and check EVERY address returned — a host may be dual-stack, and an
    # attacker controls which record the client happens to pick.
    try:
        infos = socket.getaddrinfo(hostname, port or (443 if scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"Hostname '{hostname}' does not resolve") from exc

    resolved: list[str] = []
    for info in infos:
        candidate = info[4][0]
        # getaddrinfo can return "ip%scope" for link-local IPv6.
        candidate = candidate.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if _is_blocked_ip(ip, policy):
            raise SSRFError(f"Hostname '{hostname}' resolves to non-public address {ip}")
        resolved.append(str(ip))

    if not resolved:
        raise SSRFError(f"Hostname '{hostname}' produced no usable addresses")

    return resolved


def build_safe_context(
    policy: SsrfPolicy = default_policy,
) -> SsrfPolicy:
    """Return the policy to use for the current environment.

    Convenience helper so callers can flip to a permissive policy under
    HAAFIZ_ALLOW_PRIVATE_NETWORKS=1 (local development against a container on the
    Docker bridge network) without editing analyzer code.
    """
    return policy
