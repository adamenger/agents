# PiHole Threat Intel Agent

Automated daily threat analysis of Pi-hole DNS logs using a local LLM. Classifies every domain queried on your network as benign, suspicious, malicious, or unknown — with reasoning, confidence scores, and threat indicators.

Runs entirely locally. No cloud APIs required (unless you want Claude escalation for low-confidence results).

## Quick Start (Apple Silicon / macOS)

**Prerequisites:** Docker Desktop and [Ollama](https://ollama.com) installed natively.

```bash
# 1. Pull the model (~9GB, one-time)
ollama pull qwen3:14b

# 2. Start the stack
docker-compose up -d

# 3. Point your machine's DNS at Pi-hole
#    System Preferences → Network → DNS → 127.0.0.1

# 4. Browse normally for a while, then run the agent
docker-compose run --rm threat-intel
```

That's it. Pi-hole collects DNS queries, the agent reads them directly from Pi-hole's SQLite database, sends batches to your local Ollama for classification, and stores results.

### Why Ollama runs natively (not in Docker)

Docker on macOS cannot access the Metal GPU. Benchmarks show **6x slower inference** in Docker (CPU-only) vs native Metal:

| | Native (Metal) | Docker (CPU) |
|---|---|---|
| 14B model | ~14 tok/s | ~2.3 tok/s |

The docker-compose connects to Ollama on the host via `host.docker.internal:11434`. On Linux with an NVIDIA GPU, you can uncomment the Ollama service in `docker-compose.yml` for full GPU passthrough.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Default: SQLite mode (lightweight, local)                       │
│                                                                 │
│  Pi-hole ──(FTL.db)──→ Agent ──→ Ollama (native) ──→ SQLite   │
│   DNS server         reads DB     Qwen3 14B         evaluations │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ SIEM mode: docker-compose --profile siem up -d                  │
│                                                                 │
│  Pi-hole ──→ FluentBit ──→ OpenSearch ──→ Agent ──→ OpenSearch │
│   DNS logs   parses/ships   stores logs   queries    evaluations│
│                                           │                     │
│                             Dashboards ←──┘ (visualization)     │
└─────────────────────────────────────────────────────────────────┘
```

### Swappable Backend

The agent uses a `DataSource` abstraction — swap between SQLite and OpenSearch with one env var:

| Mode | `THREAT_INTEL_DATA_SOURCE` | Best for |
|------|---------------------------|----------|
| `sqlite` (default) | Reads Pi-hole's FTL database directly | Home use, local agents, quick setup |
| `opensearch` | Reads from OpenSearch indices via FluentBit | Corporate/SIEM, multi-source correlation, dashboards |

Adding a new backend (Postgres, Splunk, Elastic, etc.) = implement the `DataSource` ABC.

## What It Does

1. Queries Pi-hole for unique domains from the last 24 hours
2. Filters out known-good domains (Google, Apple, CDNs, etc. — configurable in `config.yml`)
3. Skips domains already evaluated within the TTL window (default: 7 days)
4. Batches remaining domains (25 per batch) to the local LLM
5. LLM classifies each domain with threat level, confidence, reasoning, and indicators
6. Stores evaluations (SQLite or OpenSearch depending on mode)
7. Prints a summary report with alerts for non-benign domains

First run: ~20 min for a typical home network (~1000 unique domains after filtering).
Subsequent runs: ~1-5 min (only new domains need evaluation).

## Configuration

Three layers (highest priority wins):

1. **Environment variables** (`THREAT_INTEL_` prefix)
2. **`config.yml`** defaults section
3. **Hardcoded fallbacks** in `config.py`

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `THREAT_INTEL_DATA_SOURCE` | `sqlite` | `sqlite` or `opensearch` |
| `THREAT_INTEL_SQLITE_PIHOLE_DB` | `/etc/pihole/pihole-FTL.db` | Path to Pi-hole's FTL database |
| `THREAT_INTEL_SQLITE_EVAL_DB` | `/data/evaluations.db` | Path to evaluation storage |
| `THREAT_INTEL_OPENSEARCH_HOST` | `localhost` | OpenSearch host (SIEM mode) |
| `THREAT_INTEL_OPENSEARCH_PORT` | `9200` | OpenSearch port (SIEM mode) |
| `THREAT_INTEL_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint |
| `THREAT_INTEL_OLLAMA_MODEL` | `qwen3:14b` | Ollama model name |
| `THREAT_INTEL_BATCH_SIZE` | `25` | Domains per LLM batch |
| `THREAT_INTEL_LOOKBACK_HOURS` | `24` | Hours of DNS logs to analyze |
| `THREAT_INTEL_EVALUATION_TTL_DAYS` | `7` | Days before re-evaluating a domain |
| `THREAT_INTEL_CONFIG_PATH` | `/app/config.yml` | Path to config.yml |

### config.yml

All prompts, known-good domain lists, and output formatting strings live in `config.yml`. This keeps the Python code generic and the behavior tunable without code changes.

## SIEM Mode (FluentBit + OpenSearch)

For a full SIEM-like pipeline with log aggregation and dashboards:

```bash
# Start everything including FluentBit, OpenSearch, and Dashboards
docker-compose --profile siem up -d

# Override the agent to use OpenSearch
docker-compose run --rm \
  -e THREAT_INTEL_DATA_SOURCE=opensearch \
  -e THREAT_INTEL_OPENSEARCH_HOST=opensearch \
  threat-intel
```

OpenSearch Dashboards will be at `http://localhost:5601`.

### FluentBit Configuration

The included FluentBit config (`fluentbit/`) parses Pi-hole v5 (dnsmasq) log format and ships to OpenSearch as daily indices (`pihole-YYYY.MM.DD`). The parser extracts:

| Field | Description |
|-------|-------------|
| `domain` | Queried domain name |
| `client_or_target` | Client IP or upstream DNS target |
| `action` | `query`, `forwarded`, `reply`, `cached`, `gravity`, etc. |
| `query_type` | `A`, `AAAA`, `CNAME`, `PTR`, etc. |
| `@timestamp` | Log timestamp |

Pi-hole v6 changed the log format. If running v6, the SQLite backend (default) is recommended since it reads the FTL database directly and works with any Pi-hole version.

## Project Structure

```
pihole-threat-intel/
├── docker-compose.yml          # PiHole + agent (default), SIEM profile
├── Dockerfile
├── config.yml                  # All prompts, allowlists, output strings, defaults
├── pyproject.toml
├── fluentbit/                  # FluentBit config (SIEM mode only)
│   ├── fluent-bit.conf
│   └── parsers.conf
└── src/pihole_threat_intel/
    ├── main.py                 # Pipeline orchestrator
    ├── config.py               # Settings (env vars + config.yml defaults)
    ├── yaml_config.py          # Loads config.yml
    ├── datasource.py           # DataSource ABC
    ├── sqlite_source.py        # SQLite backend (reads FTL DB directly)
    ├── opensearch_source.py    # OpenSearch backend (SIEM mode)
    ├── agent.py                # PydanticAI agent (Ollama/Qwen3)
    ├── models.py               # Pydantic data models
    ├── domain_aggregator.py    # Filter known-good, dedup, batch
    ├── output.py               # OutputHandler ABC + StdoutHandler
    ├── known_domains.py        # Known-good domain allowlist
    └── logging_config.py       # structlog JSON to stderr
```

## Extending

### Add a new data source

Implement the `DataSource` ABC in `datasource.py`:

```python
class MySource(DataSource):
    def fetch_domain_stats(self) -> list[DomainStats]: ...
    def fetch_previous_evaluations(self) -> list[DomainEvaluation]: ...
    def fetch_already_evaluated_domains(self) -> set[str]: ...
    def store_evaluations(self, evaluations) -> int: ...
```

Then add it to `_get_datasource()` in `main.py`.

### Add a new output handler

Implement `OutputHandler` in `output.py` (e.g., Slack, SMS, email).

### Enable Claude escalation

Stubbed in `agent.py` and `config.py`. Uncomment the Claude code, set `THREAT_INTEL_ANTHROPIC_API_KEY`, and low-confidence non-benign results get a second opinion from Claude.

## Deployment (Ansible)

For dedicated server deployment (e.g., Linux with NVIDIA GPU):

```bash
ansible-playbook playbooks/pihole-threat-intel.yml
```

The Ansible role builds the Docker image, creates a systemd oneshot service, and sets up a daily cron (default: 6am). Manual trigger:

```bash
systemctl start pihole-threat-intel
journalctl -u pihole-threat-intel -f
```

## Evaluation Output

| Threat Level | Meaning |
|-------------|---------|
| `benign` | Normal, expected traffic |
| `suspicious` | Concerning patterns but not definitive (DGA-like, unusual TLD, telemetry) |
| `malicious` | Clear indicators of C2, phishing, or malware infrastructure |
| `unknown` | Insufficient information to classify |

Each evaluation includes confidence (0-100), reasoning (with slight dad humor for benign/suspicious), and specific threat indicators.
