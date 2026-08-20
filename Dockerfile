# Deployable reference image for the AuthGate Freedom Verifier HTTP API.
# Put TLS / mTLS / WAF / rate-limits at the ingress in front of this.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8000 \
    AUTHGATE_AUDIT_PATH=/data/audit.jsonl \
    AUTHGATE_BACKEND=python

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir . \
    && mkdir -p /data \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser /data /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/readyz').status==200 else 1)"

# Require AUTHGATE_ADMIN_TOKEN at runtime (readyz fails closed without it).
CMD ["authgate-server"]
