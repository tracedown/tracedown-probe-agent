"""Tests for body storage backends and upload flow."""

from __future__ import annotations

import tempfile
from pathlib import Path

from services.executor import _redact_body_bytes, _upload_bodies, init_storage
from storage.filesystem import FilesystemStorage


def test_filesystem_upload() -> None:
    """FilesystemStorage copies files and returns a file:// URI."""
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
        # Write a fake body file
        body_file = Path(src) / "call_0_response.json"
        body_file.write_text('{"status": "ok"}')

        storage = FilesystemStorage(root_dir=dst)
        ref = storage.upload(body_file, "call_0_response.json")

        assert ref.startswith("file://")
        raw_path = ref[len("file://"):]
        assert Path(raw_path).exists()
        assert Path(raw_path).read_text() == '{"status": "ok"}'


def test_filesystem_download_url() -> None:
    """FilesystemStorage returns path if file exists, None otherwise."""
    with tempfile.TemporaryDirectory() as dst:
        storage = FilesystemStorage(root_dir=dst)

        assert storage.download_url("file:///nonexistent/missing.json") is None

        target = Path(dst) / "exists.json"
        target.write_text("{}")
        uri = f"file://{target}"
        assert storage.download_url(uri) is not None


def test_upload_bodies_rewrites_paths() -> None:
    """_upload_bodies replaces local bodyPath with storage URI."""
    with tempfile.TemporaryDirectory() as bodies_dir, tempfile.TemporaryDirectory() as storage_dir:
        # Write a fake body file
        body_file = Path(bodies_dir) / "call_0_response.json"
        body_file.write_text('{"data": 42}')

        storage = FilesystemStorage(root_dir=storage_dir)
        init_storage(storage)

        result = {
            "outcome": "success",
            "calls": [
                {
                    "index": 0,
                    "response": {
                        "status": 200,
                        "bodyPath": str(body_file),
                    },
                },
                {
                    "index": 1,
                    "response": {
                        "status": 204,
                        "bodyPath": None,
                    },
                },
                {
                    "index": 2,
                    "response": None,
                },
            ],
        }

        _upload_bodies(result, [])

        # First call: bodyPath rewritten to file:// URI
        ref = result["calls"][0]["response"]["bodyPath"]
        assert ref.startswith("file://")
        assert ref != str(body_file)
        raw_path = ref[len("file://"):]
        assert Path(raw_path).exists()
        assert Path(raw_path).read_text() == '{"data": 42}'

        # Second call: no body, bodyPath stays None
        assert result["calls"][1]["response"]["bodyPath"] is None

        # Third call: no response at all, untouched
        assert result["calls"][2]["response"] is None


def test_upload_bodies_keys_are_unique_per_run() -> None:
    """Two runs of the same call filename must not collide on a storage key."""
    with tempfile.TemporaryDirectory() as storage_dir:
        storage = FilesystemStorage(root_dir=storage_dir)
        init_storage(storage)

        refs: list[str] = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as bodies_dir:
                body_file = Path(bodies_dir) / "call_0_response.json"
                body_file.write_text("{}")
                result = {
                    "calls": [
                        {"index": 0, "response": {"status": 200, "bodyPath": str(body_file)}}
                    ]
                }
                _upload_bodies(result, [])
                refs.append(result["calls"][0]["response"]["bodyPath"])

        # Same filename, different runs → distinct, namespaced keys.
        assert refs[0] != refs[1]
        assert all(r.endswith("/call_0_response.json") for r in refs)
        # The namespace segment is a random hex prefix, not the bare filename.
        assert not refs[0].endswith("bodies/call_0_response.json")


def test_upload_bodies_redacts_secrets_before_upload() -> None:
    """Secret plaintexts are masked out of the stored body bytes."""
    mask = "••••••"
    with tempfile.TemporaryDirectory() as bodies_dir, tempfile.TemporaryDirectory() as storage_dir:
        body_file = Path(bodies_dir) / "call_0_response.json"
        body_file.write_text('{"echo": "Bearer SUPERSECRET and TOK"}')

        storage = FilesystemStorage(root_dir=storage_dir)
        init_storage(storage)

        result = {
            "calls": [
                {"index": 0, "response": {"status": 200, "bodyPath": str(body_file)}}
            ]
        }
        # "TOK" is a substring of "SUPERSECRET"? No — but exercise longest-first too.
        _upload_bodies(result, ["SUPERSECRET", "TOK"])

        ref = result["calls"][0]["response"]["bodyPath"]
        stored = Path(ref[len("file://"):]).read_text()
        assert "SUPERSECRET" not in stored
        assert "TOK" not in stored
        assert mask in stored


def test_redact_body_bytes_longest_first() -> None:
    """A secret that is a substring of another is masked fully, no fragment left."""
    out = _redact_body_bytes(b"a=TOKEN123&b=TOK", ["TOK", "TOKEN123"])
    assert b"TOKEN123" not in out
    assert b"EN123" not in out


def test_redact_body_bytes_handles_binary() -> None:
    """Byte-level redaction works on non-UTF-8 content without raising."""
    data = b"\xff\xfe secret \x00\x01"
    out = _redact_body_bytes(data, ["secret"])
    assert b"secret" not in out
    assert out.startswith(b"\xff\xfe")
