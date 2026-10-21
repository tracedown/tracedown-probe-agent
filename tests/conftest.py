"""Shared test fixtures for probe-agent tests."""

from __future__ import annotations

import socket
import sys
import threading
from collections.abc import Callable, Iterator
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


@pytest.fixture
def server() -> Iterator[Callable[[Callable[[socket.socket], None]], str]]:
    """A raw TCP server whose behaviour per connection the test supplies.

    Closing every accepted socket on the way out is what ends the over-budget
    executor thread, which otherwise runs on to its own per-call timeout.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    release = threading.Event()
    accepted: list[socket.socket] = []

    def start(behaviour: Callable[[socket.socket], None]) -> str:
        def serve() -> None:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                accepted.append(conn)
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        def handle(conn: socket.socket) -> None:
            try:
                conn.recv(65536)
                behaviour(conn)
                release.wait(10)
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        return f"http://127.0.0.1:{listener.getsockname()[1]}"

    yield start
    release.set()
    listener.close()
    for conn in accepted:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()
