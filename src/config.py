"""Agent configuration via environment variables.

All settings are prefixed with ``PROBE_AGENT_`` and read from the
environment automatically by pydantic-settings.
"""

from pydantic_settings import BaseSettings


class AgentSettings(BaseSettings):
    """Probe agent configuration."""

    # Bootstrap registration
    bootstrap_token: str = ""
    scheduler_url: str = ""

    # TLS certificate paths
    ca_cert_path: str = "/certs/ca.pem"
    cert_path: str = "/certs/agent.pem"
    key_path: str = "/certs/agent-key.pem"

    # Trust-anchor pin file. At first bootstrap the agent records the SHA-256
    # fingerprints of the CA bundle it was handed (trust-on-first-use). Renewal
    # then refuses any bundle that no longer contains a pinned CA, so an on-path
    # attacker cannot swap the trust anchor for one of their own. Rotation is
    # still allowed because a make-before-break bundle keeps a pinned CA present.
    ca_pins_path: str = "/certs/ca-pins.txt"

    # Path where the agent's assigned slug is persisted at bootstrap. Renewal
    # reads it to identify itself to the scheduler. ``slug`` (if set) overrides
    # the persisted value — useful for agents bootstrapped before slugs were
    # persisted.
    slug_path: str = "/certs/agent-slug.txt"
    slug: str = ""

    # Certificate renewal. The agent rotates its client certificate before it
    # expires: it checks on startup and then every ``renew_check_hours`` and,
    # when the current cert is within ``renew_before_days`` of ``notAfter``,
    # generates a fresh keypair + CSR and calls the scheduler's renew endpoint.
    renew_before_days: int = 30
    renew_check_hours: int = 24

    # Server
    host: str = "0.0.0.0"
    port: int = 8443
    log_level: str = "info"

    # Max concurrent probe executions. Probes run synchronously in a thread
    # pool (each blocks on network I/O — DNS/connect/TLS/response), so this is
    # I/O-bound, not CPU-bound. Python's default asyncio pool is only
    # min(32, cpu+4) threads, which caps throughput hard when per-probe
    # latency is high (e.g. probing over the public internet, where each probe
    # pays a full ~0.5-1s TCP+TLS handshake). Set well above the expected
    # in-flight count: peak_rps * avg_probe_seconds.
    max_concurrency: int = 256

    # Body storage: "filesystem" or "s3"
    storage_backend: str = "filesystem"
    storage_dir: str = "/data/bodies"

    # S3-compatible object store (AWS S3, Cloudflare R2, MinIO, …) —
    # only used when storage_backend == "s3"
    s3_endpoint_url: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_bucket: str = ""
    s3_prefix: str = ""
    # "auto" suits R2 and is ignored by MinIO; AWS S3 needs the bucket region.
    s3_region: str = "auto"

    model_config = {"env_prefix": "PROBE_AGENT_"}
