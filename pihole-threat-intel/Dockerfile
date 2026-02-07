FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY config.yml .
COPY src/ src/

RUN pip install --no-cache-dir ".[opensearch]"

ENTRYPOINT ["pihole-threat-intel"]
