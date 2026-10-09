"""Tests for the SSRF guard on the website analyzer.

Each blocked case below is a real attack against a URL-fetching service. The
169.254.169.254 case in particular hands out cloud IAM credentials and is the
first thing an attacker probes on any newly deployed service.
"""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from app.core.ssrf import SSRFError, SsrfPolicy, assert_public_url


class TestCloudMetadata:
    """The classic credential-theft target."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://169.254.169.254/",
            "http://169.254.169.254:80/metadata",
        ],
    )
    def test_aws_gcp_metadata_endpoint_blocked(self, url):
        with pytest.raises(SSRFError):
            assert_public_url(url)

    def test_azure_metadata_endpoint_blocked(self):
        with pytest.raises(SSRFError):
            assert_public_url("http://169.254.169.254/metadata/instance?api-version=2021-02-01")


class TestInternalNetworks:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://127.0.0.1:3001/api/auth/me",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://[::1]/",
            "http://0.0.0.0/",
            # CGNAT range -- heavily used by Pakistani ISPs for internal infra.
            "http://100.64.0.1/",
        ],
    )
    def test_private_and_loopback_blocked(self, url):
        with pytest.raises(SSRFError):
            assert_public_url(url)

    def test_hostname_resolving_to_internal_ip_blocked(self):
        """DNS pointing a public-looking name at a private address."""
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.0.10", 443))]
        with mock.patch("app.core.ssrf.socket.getaddrinfo", return_value=fake):
            with pytest.raises(SSRFError, match="non-public"):
                assert_public_url("https://innocent-looking.example/")

    def test_dual_stack_with_one_internal_ip_blocked(self):
        """An attacker controls which record the client picks, so ALL must pass."""
        fake = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch("app.core.ssrf.socket.getaddrinfo", return_value=fake):
            with pytest.raises(SSRFError):
                assert_public_url("https://dual-stack.example/")


class TestSchemeAndPortRestrictions:
    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://internal:6379/_INFO",
            "ftp://example.com/file",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
    )
    def test_non_http_schemes_blocked(self, url):
        with pytest.raises(SSRFError):
            assert_public_url(url)

    @pytest.mark.parametrize("port", [22, 3306, 5432, 6379, 27017, 11211])
    def test_service_ports_blocked(self, port):
        with pytest.raises(SSRFError):
            assert_public_url(f"http://93.184.216.34:{port}/")

    def test_standard_ports_allowed(self):
        # 93.184.216.34 is example.com's long-standing public address.
        for url in ("http://93.184.216.34/", "https://93.184.216.34/"):
            assert assert_public_url(url) == ["93.184.216.34"]


class TestParserConfusion:
    """Payloads that exploit differences between URL parsers and HTTP clients."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://trusted.com@127.0.0.1/",
            "https://user:pass@10.0.0.1/",
            "https://127.0.0.1\\@trusted.com/",
        ],
    )
    def test_userinfo_authority_confusion_blocked(self, url):
        with pytest.raises(SSRFError):
            assert_public_url(url)

    def test_control_characters_blocked(self):
        """Newline injection to confuse validators vs clients."""
        with pytest.raises(SSRFError, match="control characters"):
            assert_public_url("http://93.184.216.34/\nX-Injected: true")

    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        """::ffff:127.0.0.1 is a bypass for naive IPv6-only checks."""
        with pytest.raises(SSRFError):
            assert_public_url("http://[::ffff:127.0.0.1]/")

    def test_missing_hostname_blocked(self):
        with pytest.raises(SSRFError):
            assert_public_url("http://")

    @pytest.mark.parametrize("url", ["", "   ", None])
    def test_empty_input_blocked(self, url):
        with pytest.raises(SSRFError):
            assert_public_url(url)  # type: ignore[arg-type]


class TestLegitimateUseIsNotBroken:
    def test_public_ipv4_literal_allowed(self):
        assert assert_public_url("https://93.184.216.34/") == ["93.184.216.34"]

    def test_public_hostname_resolves(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("app.core.ssrf.socket.getaddrinfo", return_value=fake):
            assert assert_public_url("https://example.com/") == ["93.184.216.34"]

    def test_public_ipv6_allowed_by_default(self):
        ip = "2606:2800:220:1:248:1893:25c8:1946"
        assert assert_public_url(f"https://[{ip}]/") == [ip]

    def test_fqdn_trailing_dot_tolerated(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("app.core.ssrf.socket.getaddrinfo", return_value=fake):
            assert assert_public_url("https://example.com./") == ["93.184.216.34"]

    def test_non_resolving_domain_raises_ssrf_not_socket_error(self):
        """The analyzer reports 'domain does not resolve' as a scam signal, so
        this must surface as SSRFError with a clear message, not gaierror."""
        with mock.patch("app.core.ssrf.socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with pytest.raises(SSRFError, match="does not resolve"):
                assert_public_url("https://nonexistent-domain-xyz.example/")


class TestPolicy:
    def test_dev_policy_allows_private_networks(self):
        """Local dev against a container on the Docker bridge needs this escape hatch."""
        policy = SsrfPolicy(allow_private=True)
        assert assert_public_url("http://192.168.1.50:8080/", policy=policy)
        assert assert_public_url("http://10.0.0.5/", policy=policy)

    def test_dev_policy_still_blocks_loopback_and_metadata(self):
        """The escape hatch must not open the host itself or cloud metadata."""
        policy = SsrfPolicy(allow_private=True)
        with pytest.raises(SSRFError):
            assert_public_url("http://127.0.0.1/", policy=policy)
        with pytest.raises(SSRFError):
            assert_public_url("http://169.254.169.254/", policy=policy)

    def test_dev_policy_still_blocks_ipv4_mapped_loopback(self):
        policy = SsrfPolicy(allow_private=True)
        with pytest.raises(SSRFError):
            assert_public_url("http://[::ffff:127.0.0.1]/", policy=policy)

    def test_default_ports(self):
        assert SsrfPolicy().ports == frozenset({80, 443, 8080, 8443})

    def test_custom_port_allowlist(self):
        policy = SsrfPolicy(allowed_ports=frozenset({8000}))
        assert assert_public_url("http://93.184.216.34:8000/", policy=policy)
        with pytest.raises(SSRFError):
            assert_public_url("http://93.184.216.34:443/", policy=policy)

    def test_ipv6_can_be_disabled(self):
        policy = SsrfPolicy(allow_ipv6=False)
        with pytest.raises(SSRFError):
            assert_public_url("https://[2606:2800:220:1:248:1893:25c8:1946]/", policy=policy)
