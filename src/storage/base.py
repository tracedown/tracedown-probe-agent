"""Body storage abstraction.

The Lace executor writes response bodies to a local temp directory.
After execution, the agent uploads them to the configured storage
backend and replaces local ``bodyPath`` values in the result with
storage URIs.

Storage URIs use a protocol scheme so consumers can resolve them
without knowing which backend was used:

- ``file:///data/bodies/org/svc/run/call_0.json``
- ``s3://{bucket}/{key}``
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class BodyStorage(ABC):
    """Interface for storing probe response bodies."""

    @abstractmethod
    def upload(self, local_path: Path, key: str) -> str:
        """Upload a local file to storage.

        Parameters
        ----------
        local_path:
            Path to the file on the local filesystem (written by the
            executor).
        key:
            Storage key / relative path, e.g.
            ``{orgId}/{serviceId}/{runTs}/call_0_response.json``.

        Returns
        -------
        A protocol-prefixed storage URI that replaces ``bodyPath``
        in the result:
        - Filesystem: ``file://{absolute_path}``
        - S3-compatible: ``s3://{bucket}/{key}``
        """

    @abstractmethod
    def download_url(self, uri: str) -> str | None:
        """Return a download URL/path for a stored body, or None.

        Parameters
        ----------
        uri:
            The storage URI as returned by ``upload()``.
        """
