"""Shared test fixtures for probe-agent tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Add src/ to the import path so tests resolve modules the same way the
# application does at runtime (PYTHONPATH=src).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from main import create_app


@pytest.fixture
def client() -> TestClient:
    """FastAPI test client — no mTLS, no bootstrap."""
    app = create_app()
    return TestClient(app)
