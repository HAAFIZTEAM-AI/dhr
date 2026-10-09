"""Integration tests for the FastAPI wiring in ``ai-service/app.py``.

The analyzers depend on Playwright, Whisper, pytesseract, whois, dnspython and
tldextract -- hundreds of megabytes that are not needed to test routing, CORS,
liveness or the threat-intelligence endpoints. Those modules are stubbed here so
the real ``app.py`` can be imported and exercised end to end.

What is deliberately NOT stubbed: the registry loading, the impersonation
detector and the federation. Those are the parts worth testing.
"""

import sys
import types
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Stub the heavyweight analyzer modules before app.py is imported
# ---------------------------------------------------------------------------

def _install_analyzer_stubs() -> dict:
    """Insert fake analyzer modules and return the call log."""
    calls: dict[str, list] = {"text": [], "website": [], "voice": [], "phone": [], "image": []}

    package = types.ModuleType("analyzers")
    package.__path__ = []  # mark as a package so submodule imports work
    sys.modules["analyzers"] = package

    def make(name, key, result):
        # The module is ``analyzers.<name>_analyzer`` and the callable inside it
        # is ``analyze_<name>`` -- those two are not the same string, and
        # conflating them makes every app.py import fail.
        module_name = f"analyzers.{name}_analyzer"
        module = types.ModuleType(module_name)

        async def _async_analyze(*args):
            calls[key].append(args)
            return result

        def _sync_analyze(*args):
            calls[key].append(args)
            return result

        setattr(module, f"analyze_{name}",
                _async_analyze if name == "website" else _sync_analyze)
        sys.modules[module_name] = module
        setattr(package, f"{name}_analyzer", module)

    make("text", "text", {"confidence": 42, "risk_factors": ["stub"]})
    make("website", "website", {"risk_score": 10, "is_safe": True})
    make("voice", "voice", {"confidence": 7, "risk_factors": []})
    make("phone", "phone", {"confidence": 0, "risk_factors": []})
    make("image", "image", {"confidence": 3, "risk_factors": []})
    return calls


@pytest.fixture(scope="module")
def calls():
    return _install_analyzer_stubs()


@pytest.fixture(scope="module")
def client(calls):
    from fastapi.testclient import TestClient

    import app as app_module

    with TestClient(app_module.app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def app_module(calls):
    import app as module

    return module


# ---------------------------------------------------------------------------
# Liveness -- the Dockerfile HEALTHCHECK and compose service_healthy depend on it
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_exists(self, client):
        """Regression: the Dockerfile curled /health but no route defined it,
        so the container never became healthy and the backend -- which has
        `condition: service_healthy` -- never started."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_reports_ok_and_registry_size(self, client):
        payload = client.get("/health").json()
        assert payload["status"] == "ok"
        assert payload["service"] == "haafiz-ai"
        assert payload["brands_loaded"] > 50  # the real verified_domains.txt

    def test_is_cheap(self, client):
        """A liveness probe must not depend on the thing it monitors."""
        import time

        started = time.monotonic()
        for _ in range(20):
            client.get("/health")
        assert time.monotonic() - started < 2.0


# ---------------------------------------------------------------------------
# Threat intelligence endpoints -- the answer to the VirusTotal problem
# ---------------------------------------------------------------------------

class TestIntelEndpoint:
    def test_fresh_lookalike_is_flagged_with_no_blocklist(self, client):
        """A domain registered minutes ago, on no vendor list anywhere.

        This is exactly the URL that VirusTotal reports as ``0/94 clean``.
        """
        payload = client.post(
            "/analyze/intel", json={"url": "https://secure-hbl-login.com/verify"}
        ).json()
        assert payload["label"] == "malicious"
        assert payload["probability"] >= 0.85
        assert payload["evidence"]

    def test_verified_institution_is_clean(self, client):
        payload = client.post(
            "/analyze/intel", json={"url": "https://www.hbl.com.pk/personal"}
        ).json()
        assert payload["label"] == "clean"
        assert payload["probability"] == 0.0

    def test_unrelated_domain_is_clean(self, client):
        payload = client.post("/analyze/intel", json={"url": "https://github.com"}).json()
        assert payload["label"] == "clean"

    def test_response_is_fully_serialised(self, client):
        payload = client.post("/analyze/intel", json={"url": "https://hbl.co"}).json()
        assert payload["url"] == "https://hbl.co"
        assert isinstance(payload["sources"], list)
        assert isinstance(payload["contributing"], list)
        assert isinstance(payload["unavailable"], list)
        assert "latency_ms" in payload

    def test_source_names_are_reported(self, client):
        payload = client.post(
            "/analyze/intel", json={"url": "https://secure-hbl-login.com"}
        ).json()
        names = {s["source"] for s in payload["sources"]}
        assert "brand_impersonation" in names
        assert "haafiz_registry" in names

    def test_empty_url_does_not_500(self, client):
        response = client.post("/analyze/intel", json={"url": ""})
        assert response.status_code == 200
        assert response.json()["probability"] == 0.0

    def test_hostile_url_does_not_500(self, client):
        for hostile in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:6379/",
            "https://" + "a" * 300 + ".com",
            "https://hbl.com@evil.tld/",
            "not a url at all",
        ]:
            response = client.post("/analyze/intel", json={"url": hostile})
            assert response.status_code == 200, hostile


class TestDomainEndpoint:
    def test_returns_assessment(self, client):
        payload = client.post("/analyze/domain", json={"url": "hbl-com.pk"}).json()
        assert payload["suspicious"] is True
        assert payload["impersonated_brand"] == "Habib Bank Limited"
        assert "separator_substitution" in payload["techniques"]

    def test_strips_scheme_and_path(self, client):
        full = client.post(
            "/analyze/domain", json={"url": "https://secure-hbl-login.com/a/b?c=1"}
        ).json()
        bare = client.post("/analyze/domain", json={"url": "secure-hbl-login.com"}).json()
        assert full["suspicious"] == bare["suspicious"]
        assert full["impersonated_brand"] == bare["impersonated_brand"]

    def test_clean_domain(self, client):
        payload = client.post("/analyze/domain", json={"url": "meezanbank.com"}).json()
        assert payload["suspicious"] is False
        assert payload["risk"] == 0.0

    def test_is_fast_enough_for_on_device_use(self, client):
        """The browser extension and Call Directory builder call this inline."""
        import time

        started = time.monotonic()
        for _ in range(200):
            client.post("/analyze/domain", json={"url": "secure-hbl-login.com"})
        assert time.monotonic() - started < 3.0


class TestRegistryEndpoint:
    def test_summarises_the_registry(self, client):
        payload = client.get("/intel/registry").json()
        assert payload["brands"] > 50
        assert payload["domains"] > payload["brands"]
        assert payload["problems"] == []
        assert "Habib Bank Limited" in payload["institutions"]

    def test_publishes_only_real_institutions(self, client):
        """This endpoint is public on purpose -- it must contain no secrets."""
        payload = client.get("/intel/registry").json()
        assert payload["institutions"] == sorted(payload["institutions"])
        assert all(isinstance(name, str) for name in payload["institutions"])


# ---------------------------------------------------------------------------
# Analyzer routes still work, and run off the event loop
# ---------------------------------------------------------------------------

class TestAnalyzerRoutes:
    def test_text(self, client, calls):
        response = client.post("/analyze/text", json={"text": "fraud", "language": "ur"})
        assert response.status_code == 200
        assert response.json()["confidence"] == 42
        assert calls["text"][-1] == ("fraud", "ur")

    def test_text_default_language(self, client, calls):
        client.post("/analyze/text", json={"text": "hello"})
        assert calls["text"][-1] == ("hello", "auto")

    def test_website_is_awaited(self, client):
        response = client.post("/analyze/website", json={"url": "https://example.com"})
        assert response.status_code == 200
        assert response.json()["risk_score"] == 10

    def test_voice(self, client, calls):
        client.post("/analyze/voice", json={"audio_base64": "AAA", "language": "sd"})
        assert calls["voice"][-1] == ("AAA", "sd")

    def test_phone(self, client, calls):
        client.post("/analyze/phone", json={"phone_number": "03001234567"})
        assert calls["phone"][-1] == ("03001234567",)

    def test_image(self, client, calls):
        client.post("/analyze/image", json={"image_base64": "BBB"})
        assert calls["image"][-1] == ("BBB",)

    def test_sync_analyzers_are_dispatched_off_the_event_loop(self, app_module):
        """Regression: `async def` routes called blocking analyzers directly.

        Whisper transcription takes seconds; while it ran, the event loop could
        not serve any other request. Every sync analyzer must go through
        run_in_threadpool.
        """
        import inspect

        source = inspect.getsource(app_module)
        for route in ("analyze_text", "analyze_voice", "analyze_phone", "analyze_image"):
            assert f"run_in_threadpool({route}" in source, (
                f"{route} is still called directly on the event loop"
            )

    def test_missing_required_field_is_422(self, client):
        assert client.post("/analyze/text", json={}).status_code == 422
        assert client.post("/analyze/intel", json={}).status_code == 422


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

class TestCors:
    def test_wildcard_with_credentials_is_not_configured(self, app_module):
        """Invalid per the CORS spec: browsers reject the response, so it looks
        fine in curl and fails in every real client."""
        middleware = [
            m for m in app_module.app.user_middleware
            if getattr(m.cls, "__name__", "") == "CORSMiddleware"
        ]
        assert middleware, "CORSMiddleware is not installed"
        kwargs = middleware[0].kwargs
        assert not (kwargs.get("allow_origins") == ["*"] and kwargs.get("allow_credentials"))

    def test_origins_come_from_the_environment(self, app_module):
        assert app_module._allowed_origins
        assert "*" not in app_module._allowed_origins or not app_module._allow_credentials

    def test_credentials_follow_from_the_origin_choice(self, app_module):
        if "*" in app_module._allowed_origins:
            assert app_module._allow_credentials is False
        else:
            assert app_module._allow_credentials is True

    def test_allowed_origin_gets_headers(self, client, app_module):
        origin = app_module._allowed_origins[0]
        response = client.get("/health", headers={"Origin": origin})
        assert response.headers.get("access-control-allow-origin") == origin

    def test_methods_are_not_wildcarded(self, app_module):
        middleware = [
            m for m in app_module.app.user_middleware
            if getattr(m.cls, "__name__", "") == "CORSMiddleware"
        ][0]
        assert "*" not in middleware.kwargs.get("allow_methods", [])
