# tracedown-probe-agent

The Tracedown probe agent — executes [Lace](https://lacelang.dev) probe scripts
and returns structured results. This is the process that actually makes the HTTP
calls, so you deploy one wherever you want checks to originate from.

Tracedown is a self-hosted API monitoring platform. This repository is only the
agent; it is driven by `tracedown-core-backend`.

📖 **Documentation: [tracedown.dev](https://tracedown.dev)** —
see [Probe Agents](https://tracedown.dev/install/agents/).

Stack: Python 3.10+, FastAPI, uvicorn, httpx, and the Lace validator and
executor.

## How it works

The agent is a **stateless executor**. It receives a script, its resolved
variables, and the previous run's result; it runs the script and returns the raw
ProbeResult JSON. It holds no monitoring state and makes no decisions.

A dispatch may also carry a **run budget** (`requestTimeoutMs`, milliseconds) —
a wall clock over the whole script rather than a per-call timeout. When it
expires the agent stops waiting and answers with a `timeout` result of its own,
so the scheduler learns the run is over from the agent instead of guessing. A
dispatch without one runs to whatever the script's own per-call timeouts allow.

The scheduler **dials the agent** — so the agent must be reachable inbound from
the scheduler. An agent behind NAT with no inbound route will enrol successfully
and then never receive work.

**Enrolment** is one-shot: given a bootstrap token and the gateway URL, the agent
generates an RSA-4096 keypair, sends a CSR, and stores the signed certificate,
the CA trust bundle and its slug. Once those files exist, enrolment is skipped —
which is what makes restarts safe. Certificates last a year and the agent renews
itself 30 days out, proving possession of the current key.

Enrolment is the agent's only unauthenticated moment — that one request carries
the token and receives the CA the agent pins for life — so the agent
**authenticates the gateway before the token leaves the process**. Over `https://`
the certificate is verified against the system trust store by default; there is
no configuration in which verification is silently skipped. See
[Enrolment over TLS](#enrolment-over-tls).

**Health** is not a ping: `POST /health/challenge` makes the agent run a real
Lace script to fetch a one-time token from the gateway, so a pass proves the
executor and the network both work.

## Running

The easiest path is the helper in
[tracedown-core-backend](https://github.com/tracedown/tracedown-core-backend),
which generates a token and starts the container against a running stack:

```bash
# from tracedown-core-backend
./scripts/bootstrap-agent.sh [slug]
```

Manually, against a gateway on the public internet:

```bash
docker build -t tracedown-agent .
docker run -d --name tracedown-agent \
  -e PROBE_AGENT_BOOTSTRAP_TOKEN=<one-time token> \
  -e PROBE_AGENT_SCHEDULER_URL=https://tracedown.example.com \
  -e DEPLOYMENT_ENV=production \
  tracedown-agent
```

Despite its name, `PROBE_AGENT_SCHEDULER_URL` is the **api-gateway's** base
URL — registration and certificate renewal are served there, not by the
scheduler.

Configuration is environment-driven and prefixed `PROBE_AGENT_` — the full
reference is in the [documentation](https://tracedown.dev/install/agents/).

## Enrolment over TLS

The enrolment request carries the single-use bootstrap token *and* receives the
CA bundle the agent pins for the rest of its life. If nobody authenticates the
peer on that one request, an on-path attacker reads the token and installs a CA
the agent then trusts forever. So the agent authenticates the gateway first, one
of three ways:

| Situation | Configuration |
|---|---|
| Gateway behind a publicly trusted certificate (certbot, a managed edge) | Nothing — the system trust store is the default |
| Gateway behind a private/internal CA | `PROBE_AGENT_BOOTSTRAP_CA_BUNDLE=/path/to/ca.pem` |
| Gateway certificate not chainable at all (self-signed) | `PROBE_AGENT_BOOTSTRAP_PIN_SHA256=<fingerprint>` |
| Local development only | `PROBE_AGENT_INSECURE_SKIP_BOOTSTRAP_TLS_VERIFY=true` |

Take the fingerprint the same way you take the bootstrap token — from the
operator running the gateway, out of band:

```bash
openssl s_client -connect tracedown.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Colons, a `sha256:` prefix and several comma-separated values are all accepted.
The agent opens one throwaway handshake to read the certificate, refuses to go
further unless it matches, and then makes the enrolment request trusting that
certificate and nothing else.

`PROBE_AGENT_INSECURE_SKIP_BOOTSTRAP_TLS_VERIFY` is the only way to reach an
unverified connection, it warns every time it is used, and it is **refused when
`DEPLOYMENT_ENV=production`**.

### Plain `http://` gateway URLs

`PROBE_AGENT_SCHEDULER_URL=http://…` has no transport to authenticate — the
token crosses the wire in the clear. It is what the Compose stacks use on a
private container network, so it is allowed (with a warning) outside production
and **refused when `DEPLOYMENT_ENV=production`**. In production, point the agent
at an `https://` URL that terminates TLS in front of the gateway.

Enrolment and renewal are served at `/internal/agents/…` on the gateway root, so
whatever terminates TLS has to proxy that path through — check your vhost before
switching an agent from the internal `http://` URL to the public one.

`DEPLOYMENT_ENV` is read unprefixed as well as as `PROBE_AGENT_DEPLOYMENT_ENV`,
so a stack that already sets it platform-wide needs nothing extra. Only the exact
value `production` arms these guards; unset means development.

## Testing

```bash
pytest
```

## License

Open source under the Apache License 2.0. See `LICENSE`.
