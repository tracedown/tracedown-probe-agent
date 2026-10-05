"""Tests for health and challenge-response endpoints."""

from __future__ import annotations

import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import create_app


def test_health_returns_ok(client: TestClient) -> None:
    """GET /health returns status and the version this checkout declares —
    the one place an operator can read what is actually running."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] == _declared_version()
    assert body["version"] != "0.0.0"


def _declared_version() -> str:
    with (Path(__file__).resolve().parent.parent / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def test_version_comes_from_the_pyproject_beside_src() -> None:
    """The code always runs from `src/` next to pyproject.toml, so that file is
    the version of the code — not whatever an install last recorded."""
    import config

    assert config.AGENT_VERSION == _declared_version()
    assert config.DEFAULT_USER_AGENT == f"tracedown-agent/{_declared_version()}"
    assert config._PYPROJECT == Path(__file__).resolve().parent.parent / "pyproject.toml"


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(None, id="missing file"),
        pytest.param(b"not = [toml", id="malformed"),
        pytest.param(b"\xff\xfe", id="not utf-8"),
        pytest.param(b'[project]\nname = "x"\n', id="dynamic version"),
        pytest.param(b'project = "x"\n', id="project not a table"),
        pytest.param(b'[project]\nversion = 1.0\n', id="version not a string"),
        pytest.param(b'[project]\nversion = ""\n', id="version empty"),
    ],
)
def test_unreadable_pyproject_is_a_placeholder_not_a_crash(tmp_path: Path, content) -> None:
    """`_agent_version` runs at import; nothing about the file may stop the agent."""
    import config

    pyproject = tmp_path / "pyproject.toml"
    if content is not None:
        pyproject.write_bytes(content)
    assert config._agent_version(pyproject) == "0.0.0"


def test_challenge_success() -> None:
    """POST /health/challenge runs a Lace script and returns the token."""
    app = create_app()
    tc = TestClient(app)

    with patch("services.executor._run_health_sync", return_value="abc123") as mock:
        resp = tc.post("/health/challenge", json={
            "challenge_id": "ch-001",
            "token_url": "https://scheduler.internal/internal/health/token/ch-001",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["challenge_id"] == "ch-001"
    assert body["token"] == "abc123"
    assert body["success"] is True
    assert body["error"] is None
    assert body["elapsed_ms"] >= 0
    mock.assert_called_once_with("https://scheduler.internal/internal/health/token/ch-001")


def test_challenge_failure() -> None:
    """POST /health/challenge reports failure when the executor errors."""
    app = create_app()
    tc = TestClient(app)

    with patch("services.executor._run_health_sync", side_effect=RuntimeError("health script failed: Connection refused")):
        resp = tc.post("/health/challenge", json={
            "challenge_id": "ch-002",
            "token_url": "https://scheduler.internal/internal/health/token/ch-002",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["challenge_id"] == "ch-002"
    assert body["token"] is None
    assert body["success"] is False
    assert "Connection refused" in body["error"]
