"""Agent configuration via environment variables.

All settings are prefixed with ``PROBE_AGENT_`` and read from the
environment automatically by pydantic-settings.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


def _agent_version() -> str:
    """Installed package version, or a placeholder when the agent runs from a
    source tree that was never installed (tests, ``python -m``)."""
    try:
        return _package_version("tracedown-probe-agent")
    except PackageNotFoundError:
        return "0.0.0"


#: Default value for :attr:`AgentSettings.user_agent` — the product name and
#: its version, nothing more.
DEFAULT_USER_AGENT = f"tracedown-agent/{_agent_version()}"


class AgentSettings(BaseSettings):
    """Probe agent configuration."""

    # Bootstrap registration
    bootstrap_token: str = ""
    scheduler_url: str = ""

    # --- Bootstrap transport trust -------------------------------------------
    # The registration call is the one moment the agent has nothing to verify
    # the gateway with: it carries the single-use bootstrap token and receives
    # the CA bundle the agent then pins for life. An unauthenticated peer there
    # means an on-path attacker reads the token and installs a CA of their own,
    # so the peer is always authenticated somehow. See mtls/bootstrap_trust.py.

    # PEM bundle of the CA that issued the gateway's certificate. Set it when
    # the gateway is fronted by a private/internal CA the system trust store
    # does not carry. Empty = verify against the system trust store.
    bootstrap_ca_bundle: str = ""

    # SHA-256 fingerprint of the certificate the gateway presents, as printed by
    # `openssl x509 -noout -fingerprint -sha256` (colons optional, several
    # allowed, comma- or space-separated). This is out-of-band pinning: the
    # fingerprint travels with the bootstrap token, which already has to reach
    # the operator out of band. Takes precedence over bootstrap_ca_bundle.
    bootstrap_pin_sha256: str = ""

    # Local-development opt-out: skip verification of the gateway's certificate
    # at bootstrap. Named for what it costs, refused when deployment_env is
    # production, and logged at WARNING every time it is used. Nothing else in
    # the agent can reach an unverified TLS connection.
    insecure_skip_bootstrap_tls_verify: bool = False

    # Deployment environment, mirroring the backend's SecretGuard: only the exact
    # value "production" arms the guards above, everything else (unset included)
    # is development. Reads the platform-wide DEPLOYMENT_ENV as well as the
    # agent-prefixed name, so a stack that already sets it needs no extra config.
    deployment_env: str = Field(
        default="dev",
        validation_alias=AliasChoices("PROBE_AGENT_DEPLOYMENT_ENV", "DEPLOYMENT_ENV"),
    )

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

    # How probes identify themselves to the servers they call.
    #
    # The executor would otherwise announce itself generically (lace-spec §3.6
    # defaults to `lace-probe/<version> (<implementation>)`), which names the
    # scripting language rather than the thing making the requests — no use to
    # someone reading their own access log and trying to find out who we are.
    # §3.6 exists for exactly this: a host platform sets its own fleet
    # identifier and the executor sends it verbatim.
    #
    # An operator who publishes a page explaining the traffic appends a
    # "+<url>" to it, e.g. `tracedown-agent/1.2.3 (+https://example.com/agent)`.
    # That is also what separates one operator's fleet from every other install
    # in a log: the bare default says only "some Tracedown".
    user_agent: str = DEFAULT_USER_AGENT

    # --- Target-egress policy (SSRF hardening) -------------------------------
    # The agent is the process that resolves DNS and opens the socket, so it is
    # where a tenant probe that 30x-es to an internal address (or points DNS at
    # one) is actually stopped. When enabled, the executor is handed an egress
    # guard (services/egress_guard.py) that refuses loopback, link-local,
    # carrier-grade-NAT, RFC1918 / ULA private ranges, and internal hostnames —
    # checked on the initial request and re-checked on every redirect hop.
    #
    # None = auto: on when DEPLOYMENT_ENV=production, off otherwise. This keeps
    # dev and the Compose/e2e stacks (which probe internal test targets on the
    # private network) working, while the hosted deployment enforces it. Set
    # PROBE_AGENT_EGRESS_GUARD explicitly to force it on or off.
    egress_guard: bool | None = None

    # Refuse a script's `security.rejectInvalidCerts: false` opt-out and enforce
    # TLS verification regardless. The Lace feature stays intact (spec default);
    # this is a host override for hosted deployments where a tenant must not be
    # able to turn certificate checking off. Same auto/None semantics as above.
    force_tls_verify: bool | None = None

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

    # populate_by_name so fields carrying a validation_alias (deployment_env)
    # can still be set by field name when AgentSettings is constructed directly.
    model_config = {"env_prefix": "PROBE_AGENT_", "populate_by_name": True}

    @property
    def is_production(self) -> bool:
        """Only the exact value "production" arms the production-gated guards,
        mirroring the backend's SecretGuard and the bootstrap trust checks."""
        return self.deployment_env == "production"

    @property
    def egress_guard_enabled(self) -> bool:
        """Whether to install the target-egress guard. Explicit setting wins;
        otherwise on in production, off everywhere else."""
        if self.egress_guard is not None:
            return self.egress_guard
        return self.is_production

    @property
    def force_tls_verify_enabled(self) -> bool:
        """Whether to override a script's rejectInvalidCerts=false opt-out.
        Explicit setting wins; otherwise on in production, off elsewhere."""
        if self.force_tls_verify is not None:
            return self.force_tls_verify
        return self.is_production
