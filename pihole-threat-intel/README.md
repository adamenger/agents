# PiHole Threat Intel Agent

> Local LLM + public threat intel feeds scan your Pi-hole DNS logs and classify every domain on your network.

Two ways to run it — pick whichever fits.

---

## Option A: Quick & Easy

**Just Pi-hole + the agent.** No extra infrastructure. Agent reads Pi-hole's SQLite database directly.

```bash
ollama pull qwen3:14b            # one-time, ~9GB
docker-compose up -d             # starts Pi-hole + agent
```

Point your DNS at `127.0.0.1`. Browse for a bit. Then:

```bash
docker-compose run --rm threat-intel
```

That's it. You get a threat report in your terminal.

---

## Option B: Full SIEM Pipeline

**Pi-hole + FluentBit + OpenSearch + Dashboards + MailHog.** DNS logs indexed in real time, email reports, and a search/visualization layer.

```bash
ollama pull qwen3:14b
docker-compose --profile siem up -d
```

This starts everything:

- **Pi-hole** — DNS on `:53`, web UI at `localhost:8080/admin`
- **FluentBit** — tails Pi-hole logs, ships to OpenSearch
- **OpenSearch** — indexes logs as `pihole-YYYY.MM.DD`
- **Dashboards** — visualize at `localhost:5601`
- **MailHog** — email inbox at `localhost:8025`

Run the agent with email output:

```bash
docker-compose run --rm -e THREAT_INTEL_EMAIL_ENABLED=true threat-intel
```

> To switch the agent to read from OpenSearch instead of SQLite, set `THREAT_INTEL_DATA_SOURCE=opensearch` in `docker-compose.yml`.

---

## How It Works

```
Pi-hole DNS logs
  → Filter known-good domains (Google, Apple, CDNs, etc.)
  → Enrich with public threat intel (~2-4 seconds for 25 domains):
      • Quad9 / Cloudflare DNSBL (blocked = malicious)
      • Spamhaus DBL (spam / phishing / malware / C2)
      • SURBL (phishing / malware)
      • RDAP (domain age — new domains are suspicious)
      • AlienVault OTX (community threat reports)
      • DNS records (A, MX, NS, TXT)
  → LLM classifies each domain with all intel pre-loaded (one call)
  → Store results, emit report (stdout + email)
```

All enrichment runs in parallel. The LLM gets a single prompt with structured intel data — no tool-calling round trips.

---

## Which One?

| | Quick & Easy | Full SIEM |
|---|---|---|
| Setup | 2 containers | 6 containers |
| Storage | SQLite (local file) | OpenSearch (indexed, searchable) |
| Dashboards | No | Yes (`localhost:5601`) |
| Email reports | No | Yes (`localhost:8025`) |
| Resource usage | ~512MB RAM | ~1.5GB RAM |
| Best for | Personal use, trying it out | Long-term monitoring, visualization |

---

## Mac Users

Install [Ollama](https://ollama.com) natively — Docker can't access Apple Silicon GPU, making inference ~6x slower. The agent connects to your host Ollama automatically via `host.docker.internal:11434`.

---

## Tuning

Everything's in `config.yml` — prompts, domain allowlists, output format.

Env vars (`THREAT_INTEL_*`) override config. The important ones:

| What | Env Var | Default |
|------|---------|---------|
| Backend | `DATA_SOURCE` | `sqlite` |
| Model | `OLLAMA_MODEL` | `qwen3:14b` |
| Batch size | `BATCH_SIZE` | `25` |
| Lookback | `LOOKBACK_HOURS` | `24` |
| Cache TTL | `EVALUATION_TTL_DAYS` | `7` |
| Email | `EMAIL_ENABLED` | `false` |
| SMTP host | `SMTP_HOST` | `mailhog` |

(All prefixed with `THREAT_INTEL_`)

---

## Extending

- **New data source?** Implement the `DataSource` ABC (4 methods).
- **New output?** Implement `OutputHandler` (Slack, SMS, whatever).
- **New enrichment source?** Add to `enrichment.py` — runs in parallel with existing lookups.
- **Want Claude as backup?** Stubbed and ready — just uncomment + add API key.
