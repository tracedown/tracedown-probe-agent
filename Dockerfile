# Dependencies come from the committed uv.lock, not from whatever PyPI happens
# to hold on build day. uv only turns the lock into a hash-pinned requirements
# file; it does that in a throwaway stage so the runtime image keeps plain
# site-packages and carries no uv.
FROM python:3.13-slim AS deps

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.12.10 /uv /bin/uv

# --no-emit-project: the agent declares no packages and runs from PYTHONPATH,
# so installing it would contribute nothing but its dependencies, which the
# export already lists. --no-dev leaves pytest/ruff out of the image.
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt > /tmp/requirements.txt

FROM python:3.13-slim

WORKDIR /app

# --require-hashes: every requirement is pinned to the exact artifact hashes
# recorded in the lock, so the build fails rather than installing something
# else.
COPY --from=deps /tmp/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY src/ ./src/

RUN mkdir -p /certs

ENV PYTHONPATH=/app/src

EXPOSE 8443

# Run main.py directly (not `uvicorn main:app`) so the __main__ block bootstraps
# the certificate and applies the mTLS server context. Invoking uvicorn on the
# app factory skips that block and would serve unauthenticated plain HTTP on the
# mTLS port. Host/port come from PROBE_AGENT_HOST/PROBE_AGENT_PORT.
CMD ["python", "src/main.py"]
