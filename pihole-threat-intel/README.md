# PiHole Threat Intel Agent

Automated daily threat analysis of Pi-hole DNS logs using a local LLM (Qwen3 14B via Ollama). Queries OpenSearch for DNS logs, filters known-good domains, evaluates unknowns in batches via structured output, and stores results back in OpenSearch.

## How It Works

```
Pi-hole DNS logs
  → FluentBit parses & ships to OpenSearch (daily indices: pihole-YYYY.MM.DD)
  → This agent queries OpenSearch for last 24h of queries
  → Filters out known-good domains (Google, Apple, CDNs, etc.)
  → Skips domains already evaluated within TTL (7 days)
  → Batches remaining domains (25 per batch) to Ollama
  → LLM classifies each as benign/suspicious/malicious/unknown
  → Stores evaluations in OpenSearch (pihole-evaluations index)
  → Prints summary report with alerts for non-benign domains
```

Subsequent runs are fast (~1-5 min) because only new domains need evaluation. First run takes ~20 min for a typical home network (~1000 unique domains after filtering).

## Prerequisites

### 1. OpenSearch

An OpenSearch instance with Pi-hole logs indexed. The agent expects daily indices with prefix `pihole-` (e.g., `pihole-2026.02.06`) containing these fields:

| Field | Type | Description |
|-------|------|-------------|
| `domain` | keyword | Queried domain name |
| `client_or_target` | keyword | Client IP or upstream target |
| `action` | keyword | `query`, `forwarded`, `reply`, `cached`, `gravity`, etc. |
| `query_type` | keyword | `A`, `AAAA`, `CNAME`, `PTR`, etc. |
| `@timestamp` | date | Log timestamp |

The agent creates a `pihole-evaluations` index automatically on first run.

### 2. FluentBit (or equivalent)

Something needs to ship Pi-hole logs to OpenSearch. The reference setup uses FluentBit with this parser:

```ini
[PARSER]
    Name          pihole
    Format        regex
    Regex         ^(?<time>[A-Za-z]{3} [ \d]{2} \d{2}:\d{2}:\d{2}) dnsmasq\[(?<pid>\d+)\]: (?<action>query|forwarded|reply|cached|config|gravity|blacklist|regex)\[(?<query_type>[A-Z0-9]+)\] (?<domain>\S+) (from|to) (?<client_or_target>\S+)$
    Time_Key      time
    Time_Format   %b %d %H:%M:%S
```

And this output:

```ini
[OUTPUT]
    Name            opensearch
    Match           pihole.*
    Host            localhost
    Port            9200
    Suppress_Type_Name On
    Logstash_Format On
    Logstash_Prefix pihole
    Time_Key        @timestamp
```

Any log shipper that produces the same index structure will work.

### 3. Ollama

A running [Ollama](https://ollama.com) instance with the model pulled:

```bash
ollama pull qwen3:14b
```

Qwen3 14B requires ~12GB VRAM (Q4_K_M quantization). It supports native tool calling which PydanticAI uses for structured output.

## Configuration

All configuration comes from three layers (highest priority wins):

1. **Environment variables** (prefix `THREAT_INTEL_`) — set by Ansible/systemd in production
2. **`config.yml` defaults section** — generic defaults for local development
3. **Hardcoded fallbacks** in `config.py` — last resort if config.yml is missing

### config.yml

The `defaults:` section holds connection settings and tuning parameters:

```yaml
defaults:
  opensearch_host: "localhost"
  opensearch_port: 9200
  ollama_base_url: "http://localhost:11434"
  ollama_model: "qwen3:14b"
  batch_size: 25
  lookback_hours: 24
  evaluation_ttl_days: 7
```

The `prompts:` section holds all LLM system/user prompts. The `known_domains:` section holds the allowlist of domains to skip (Google, Apple, CDNs, etc.). The `output:` section holds report formatting strings.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `THREAT_INTEL_OPENSEARCH_HOST` | `localhost` | OpenSearch hostname |
| `THREAT_INTEL_OPENSEARCH_PORT` | `9200` | OpenSearch port |
| `THREAT_INTEL_OPENSEARCH_PIHOLE_INDEX_PREFIX` | `pihole` | Index prefix for pihole logs |
| `THREAT_INTEL_OPENSEARCH_EVALUATIONS_INDEX` | `pihole-evaluations` | Index for storing evaluations |
| `THREAT_INTEL_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |
| `THREAT_INTEL_OLLAMA_MODEL` | `qwen3:14b` | Ollama model name |
| `THREAT_INTEL_BATCH_SIZE` | `25` | Domains per LLM batch |
| `THREAT_INTEL_LOOKBACK_HOURS` | `24` | Hours of logs to query |
| `THREAT_INTEL_PREVIOUS_EVALUATIONS_COUNT` | `20` | Recent evaluations for learning context |
| `THREAT_INTEL_EVALUATION_TTL_DAYS` | `7` | Days before re-evaluating a domain |
| `THREAT_INTEL_CONFIG_PATH` | `/app/config.yml` | Path to config.yml |

## Running Locally

```bash
# Install
pip install -e .

# Point at your OpenSearch and Ollama
export THREAT_INTEL_OPENSEARCH_HOST=<your-opensearch-host>
export THREAT_INTEL_OLLAMA_BASE_URL=http://<your-ollama-host>:11434
export THREAT_INTEL_CONFIG_PATH=./config.yml

# Run
pihole-threat-intel
```

## Docker

```bash
docker build -t pihole-threat-intel .
docker run --rm --network=host \
  -e THREAT_INTEL_OPENSEARCH_HOST=<your-opensearch-host> \
  -e THREAT_INTEL_OLLAMA_BASE_URL=http://<your-ollama-host>:11434 \
  pihole-threat-intel
```

## Deployment (Ansible)

The Ansible role at `roles/pihole-threat-intel/` handles:
- Building the Docker image on the target host
- Creating a systemd oneshot service
- Setting up a daily cron job (default: 6am)

```bash
ansible-playbook playbooks/pihole-threat-intel.yml
```

Manual trigger after deployment:
```bash
systemctl start pihole-threat-intel
journalctl -u pihole-threat-intel -f
```

## Architecture

```
src/pihole_threat_intel/
├── main.py               # Pipeline orchestrator
├── config.py             # Settings (env vars + config.yml defaults)
├── yaml_config.py        # Loads config.yml (prompts, known domains, output strings)
├── opensearch_client.py  # Read pihole logs, read/write evaluations
├── domain_aggregator.py  # Filter known-good, dedup already-evaluated, batch
├── agent.py              # PydanticAI agent (Ollama/Qwen3)
├── models.py             # Pydantic data models (ThreatLevel, DomainEvaluation, etc.)
├── output.py             # OutputHandler ABC + StdoutHandler
├── known_domains.py      # Known-good domain allowlist from config.yml
└── logging_config.py     # structlog JSON to stderr
```

## Evaluation Output

Each domain gets classified as:

| Threat Level | Meaning |
|-------------|---------|
| `benign` | Normal, expected traffic |
| `suspicious` | Concerning patterns but not definitive (DGA-like, unusual TLD, telemetry) |
| `malicious` | Clear indicators of C2, phishing, or malware infrastructure |
| `unknown` | Insufficient information to classify |

Evaluations include confidence (0-100), reasoning, and specific threat indicators (e.g., "DGA pattern", "typosquatting", "known malicious TLD").

## Future: Claude Escalation

The code includes stubbed support for escalating low-confidence non-benign results to Claude via the Anthropic API. To enable:

1. Uncomment the Claude-related code in `agent.py`, `config.py`, and `pyproject.toml`
2. Set `THREAT_INTEL_ANTHROPIC_API_KEY`
3. Domains where the local model is uncertain get a second opinion from Claude
