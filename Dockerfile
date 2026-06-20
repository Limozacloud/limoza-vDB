# ── Stage 1: build trivy-db-to ────────────────────────────────────────────────
FROM golang:1.26-alpine AS go-builder
RUN go install github.com/k1LoW/trivy-db-to@latest

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.14-slim
RUN apt-get update && apt-get install -y --no-install-recommends git wget gosu zstd bzip2 xz-utils && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /go/bin/trivy-db-to /usr/local/bin/trivy-db-to
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN wget -qO /usr/local/bin/pgschema \
    https://github.com/pgplex/pgschema/releases/download/v1.10.0/pgschema-1.10.0-linux-amd64 \
    && chmod +x /usr/local/bin/pgschema
RUN useradd -u 1000 -m ingest && mkdir -p /data
WORKDIR /app
COPY schema.sql .
COPY ingest/ ./ingest/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R ingest:ingest /app \
    && printf '#!/bin/sh\nexec gosu ingest python -m ingest.run import "$@"\n' > /usr/local/bin/import \
    && chmod +x /usr/local/bin/import
ENTRYPOINT ["/entrypoint.sh"]
