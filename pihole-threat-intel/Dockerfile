FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils curl whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY config.yml .
COPY src/ src/

RUN pip install --no-cache-dir ".[opensearch]"

ENTRYPOINT ["pihole-threat-intel"]
