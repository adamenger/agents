# PiHole Threat Intel Agent

> Local LLM scans your Pi-hole DNS logs and tells you if anything looks sketchy.

## Get Running in 60 Seconds

```bash
ollama pull qwen3:14b          # one-time, ~9GB
docker-compose up -d            # starts Pi-hole + agent
```

Point your DNS at `127.0.0.1`. Browse for a bit. Then:

```bash
docker-compose run --rm threat-intel
```

Done. You'll get a report classifying every domain on your network.

> **Mac users:** Install [Ollama](https://ollama.com) natively — Docker can't use your GPU, making it 6x slower.

---

## What Happens

```
Pi-hole → Agent reads its DB → Ollama classifies domains → stores results
```

- Filters out known-good stuff (Google, Apple, CDNs)
- Skips domains it already checked (7-day cache)
- ~20 min first run, ~1-5 min after that

---

## Want the Full SIEM Experience?

```bash
docker-compose --profile siem up -d
```

Adds FluentBit + OpenSearch + Dashboards. Visualize at `localhost:5601`.

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

(All prefixed with `THREAT_INTEL_`)

---

## Extending

- **New data source?** Implement the `DataSource` ABC (4 methods).
- **New output?** Implement `OutputHandler` (Slack, SMS, whatever).
- **Want Claude as backup?** Stubbed and ready — just uncomment + add API key.
