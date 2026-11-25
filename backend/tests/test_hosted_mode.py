"""Tests for the pieces that only matter once the app is hosted: target validation,
optional password, and the in-container (subprocess) sandbox mode."""
import asyncio
import base64
import json
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.security import check_basic, validate_target  # noqa: E402
from sandbox import orchestrator as orch  # noqa: E402


class TestValidateTarget:
    @pytest.mark.parametrize("bad", [
        "http://127.0.0.1:6379",             # the container's own Redis
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data",  # cloud metadata endpoint
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://",
    ])
    def test_rejects_internal_and_non_http(self, bad):
        with pytest.raises(ValueError):
            validate_target(bad)

    def test_accepts_public_ip_and_adds_scheme(self):
        assert validate_target("8.8.8.8/path") == "http://8.8.8.8/path"
        assert validate_target("https://8.8.4.4") == "https://8.8.4.4"

    def test_rejects_overlong_url(self):
        with pytest.raises(ValueError):
            validate_target("http://8.8.8.8/" + "a" * 3000)


class TestBasicAuth:
    def test_open_when_no_password_configured(self, monkeypatch):
        monkeypatch.delenv("BASIC_AUTH_PASSWORD", raising=False)
        assert check_basic(None)

    def test_requires_matching_credentials(self, monkeypatch):
        monkeypatch.setenv("BASIC_AUTH_PASSWORD", "s3cret")
        monkeypatch.setenv("BASIC_AUTH_USER", "admin")
        good = "Basic " + base64.b64encode(b"admin:s3cret").decode()
        bad = "Basic " + base64.b64encode(b"admin:wrong").decode()
        assert check_basic(good)
        assert not check_basic(bad)
        assert not check_basic(None)
        assert not check_basic("Bearer abc")
        assert not check_basic("Basic !!!notbase64")


def _orchestrator():
    return orch.SandboxOrchestrator(job_queue=None, ws_manager=None)


def _runner(tmp_path, body: str) -> str:
    p = tmp_path / "runner.py"
    p.write_text(textwrap.dedent(body))
    return str(p)


class TestSubprocessSandbox:
    def test_success_returns_runner_output(self, tmp_path, monkeypatch):
        monkeypatch.setattr(orch, "SANDBOX_RUNNER", _runner(tmp_path, """
            import argparse, json
            ap = argparse.ArgumentParser(); ap.add_argument("--url"); ap.add_argument("--out")
            a = ap.parse_args()
            json.dump({"final_url": a.url, "network_requests": [], "logs": []}, open(a.out, "w"))
        """))
        data = asyncio.run(_orchestrator()._run_subprocess("https://example.com"))
        assert data["final_url"] == "https://example.com"
        assert data["sandbox_mode"] == "subprocess"

    def test_runner_error_fails_the_job_instead_of_faking_a_verdict(self, tmp_path, monkeypatch):
        monkeypatch.setattr(orch, "SANDBOX_RUNNER", _runner(tmp_path, """
            import argparse, json
            ap = argparse.ArgumentParser(); ap.add_argument("--url"); ap.add_argument("--out")
            json.dump({"error": "net::ERR_NAME_NOT_RESOLVED"}, open(ap.parse_args().out, "w"))
        """))
        with pytest.raises(RuntimeError, match="ERR_NAME_NOT_RESOLVED"):
            asyncio.run(_orchestrator()._run_subprocess("https://nope.invalid"))

    def test_crash_without_output_is_reported(self, tmp_path, monkeypatch):
        monkeypatch.setattr(orch, "SANDBOX_RUNNER", _runner(tmp_path, "raise SystemExit('boom')"))
        with pytest.raises(RuntimeError, match="no result"):
            asyncio.run(_orchestrator()._run_subprocess("https://example.com"))

    def test_hung_runner_is_killed_on_timeout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(orch, "SANDBOX_TIMEOUT", 1)
        monkeypatch.setattr(orch, "SANDBOX_RUNNER", _runner(tmp_path, "import time; time.sleep(30)"))
        with pytest.raises(RuntimeError, match="timed out"):
            asyncio.run(_orchestrator()._run_subprocess("https://example.com"))
        json.dumps({})  # keep json import used
