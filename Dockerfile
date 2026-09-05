FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir . lacelang-validator lacelang-executor

COPY src/ ./src/

RUN mkdir -p /certs

ENV PYTHONPATH=/app/src

EXPOSE 8443

# Run main.py directly (not `uvicorn main:app`) so the __main__ block bootstraps
# the certificate and applies the mTLS server context. Invoking uvicorn on the
# app factory skips that block and would serve unauthenticated plain HTTP on the
# mTLS port. Host/port come from PROBE_AGENT_HOST/PROBE_AGENT_PORT.
CMD ["python", "src/main.py"]
