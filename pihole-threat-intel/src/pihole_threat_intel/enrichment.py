"""Pre-enrichment pipeline: gather threat intel from public sources before LLM evaluation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import structlog

from .models import DomainStats

log = structlog.get_logger()


@dataclass
class EnrichedDomain:
    """Domain stats + all enrichment data from public sources."""

    stats: DomainStats

    # DNS records
    dns_a: list[str] = field(default_factory=list)
    dns_mx: list[str] = field(default_factory=list)
    dns_ns: list[str] = field(default_factory=list)
    dns_txt: list[str] = field(default_factory=list)

    # DNSBL results
    quad9_blocked: bool | None = None
    cloudflare_blocked: bool | None = None
    spamhaus_result: str | None = None  # e.g. "phishing", "malware", "botnet_cc"
    surbl_result: str | None = None  # e.g. "phishing", "malware"

    # RDAP / domain age
    domain_age_days: int | None = None
    registrar: str | None = None
    creation_date: str | None = None

    # AlienVault OTX
    otx_pulse_count: int | None = None
    otx_malware_count: int | None = None
    otx_tags: list[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        return self.stats.domain

    def format_for_prompt(self) -> str:
        """Format enrichment data as a concise string for the LLM prompt."""
        parts = [
            f"- {self.domain} | queries: {self.stats.query_count} "
            f"| clients: {', '.join(self.stats.unique_clients[:5])} "
            f"| types: {', '.join(self.stats.query_types)}"
        ]

        signals = []

        # DNSBL signals
        if self.quad9_blocked:
            signals.append("BLOCKED by Quad9 (malicious)")
        if self.cloudflare_blocked:
            signals.append("BLOCKED by Cloudflare (malicious)")
        if self.spamhaus_result:
            signals.append(f"Spamhaus: {self.spamhaus_result}")
        if self.surbl_result:
            signals.append(f"SURBL: {self.surbl_result}")

        # Domain age
        if self.domain_age_days is not None:
            if self.domain_age_days < 30:
                signals.append(f"Domain age: {self.domain_age_days} days (NEW)")
            elif self.domain_age_days < 365:
                signals.append(f"Domain age: {self.domain_age_days} days")
        if self.registrar:
            signals.append(f"Registrar: {self.registrar}")

        # OTX
        if self.otx_pulse_count and self.otx_pulse_count > 0:
            signals.append(f"AlienVault OTX: {self.otx_pulse_count} threat reports")
        if self.otx_malware_count and self.otx_malware_count > 0:
            signals.append(f"OTX malware samples: {self.otx_malware_count}")

        # DNS records (brief)
        if self.dns_a:
            signals.append(f"A: {', '.join(self.dns_a[:3])}")
        if self.dns_mx:
            signals.append(f"MX: {', '.join(self.dns_mx[:2])}")
        if self.dns_ns:
            signals.append(f"NS: {', '.join(self.dns_ns[:2])}")

        if signals:
            parts.append(f"  Intel: {' | '.join(signals)}")
        else:
            parts.append("  Intel: no signals (not listed in any blocklist)")

        return "\n".join(parts)


async def _resolve(domain: str, qtype: str, server: str = "") -> list[str]:
    """Run a dig query and return results as a list of strings."""
    cmd = ["dig", "+short", "+time=3", "+tries=1"]
    if server:
        cmd.append(f"@{server}")
    cmd.extend([domain, qtype])
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        lines = [l.strip() for l in stdout.decode().strip().splitlines() if l.strip()]
        return lines
    except (asyncio.TimeoutError, FileNotFoundError):
        return []


async def _check_quad9(domain: str) -> bool | None:
    """Check if Quad9 blocks this domain (compares filtered vs unfiltered)."""
    try:
        filtered, unfiltered = await asyncio.gather(
            _resolve(domain, "A", "9.9.9.9"),
            _resolve(domain, "A", "9.9.9.10"),
        )
        if not filtered and unfiltered:
            return True  # Quad9 blocked it
        return False
    except Exception:
        return None


async def _check_cloudflare(domain: str) -> bool | None:
    """Check if Cloudflare for Families blocks this domain."""
    try:
        filtered, unfiltered = await asyncio.gather(
            _resolve(domain, "A", "1.1.1.2"),
            _resolve(domain, "A", "1.1.1.1"),
        )
        if filtered and any(ip == "0.0.0.0" for ip in filtered) and unfiltered:
            return True
        if not filtered and unfiltered:
            return True
        return False
    except Exception:
        return None


async def _check_spamhaus(domain: str) -> str | None:
    """Query Spamhaus DBL. Returns threat category or None if clean."""
    results = await _resolve(f"{domain}.dbl.spamhaus.org", "A")
    if not results:
        return None
    code_map = {
        "127.0.1.2": "spam",
        "127.0.1.4": "phishing",
        "127.0.1.5": "malware",
        "127.0.1.6": "botnet_cc",
        "127.0.1.102": "abused_spam",
        "127.0.1.104": "abused_phishing",
        "127.0.1.105": "abused_malware",
        "127.0.1.106": "abused_botnet_cc",
    }
    for ip in results:
        if ip in code_map:
            return code_map[ip]
    return None


async def _check_surbl(domain: str) -> str | None:
    """Query SURBL. Returns threat category or None if clean."""
    results = await _resolve(f"{domain}.multi.surbl.org", "A")
    if not results:
        return None
    categories = []
    for ip in results:
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                code = int(parts[3])
                if code & 8:
                    categories.append("phishing")
                if code & 16:
                    categories.append("malware")
                if code & 64:
                    categories.append("abuse")
                if code & 128:
                    categories.append("cracked")
            except ValueError:
                continue
    return ", ".join(categories) if categories else None


async def _check_rdap(domain: str) -> tuple[int | None, str | None, str | None]:
    """Query RDAP for domain age and registrar. Returns (age_days, registrar, creation_date)."""
    try:
        import json
        from datetime import datetime, timezone

        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--max-time", "5", f"https://rdap.org/domain/{domain}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        data = json.loads(stdout.decode())

        creation_date = None
        registrar = None

        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate", "")[:10]

        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for entry in vcard:
                    if entry[0] == "fn":
                        registrar = entry[3]
                        break

        age_days = None
        if creation_date:
            try:
                created = datetime.strptime(creation_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
            except ValueError:
                pass

        return age_days, registrar, creation_date
    except Exception:
        return None, None, None


async def _check_otx(domain: str) -> tuple[int | None, int | None, list[str]]:
    """Query AlienVault OTX for threat pulses. Returns (pulse_count, malware_count, tags)."""
    try:
        import json

        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--max-time", "5",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        data = json.loads(stdout.decode())

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        malware_count = len(data.get("malware", {}).get("data", []))
        tags = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", [])[:3])

        return pulse_count, malware_count, list(set(tags))[:10]
    except Exception:
        return None, None, []


async def _enrich_one(stats: DomainStats) -> EnrichedDomain:
    """Enrich a single domain with all sources in parallel."""
    domain = stats.domain
    enriched = EnrichedDomain(stats=stats)

    # Run all lookups in parallel
    (
        dns_a, dns_mx, dns_ns, dns_txt,
        quad9, cloudflare, spamhaus, surbl,
        (age, registrar, created),
        (pulses, malware, tags),
    ) = await asyncio.gather(
        _resolve(domain, "A"),
        _resolve(domain, "MX"),
        _resolve(domain, "NS"),
        _resolve(domain, "TXT"),
        _check_quad9(domain),
        _check_cloudflare(domain),
        _check_spamhaus(domain),
        _check_surbl(domain),
        _check_rdap(domain),
        _check_otx(domain),
    )

    enriched.dns_a = dns_a
    enriched.dns_mx = dns_mx
    enriched.dns_ns = dns_ns
    enriched.dns_txt = dns_txt
    enriched.quad9_blocked = quad9
    enriched.cloudflare_blocked = cloudflare
    enriched.spamhaus_result = spamhaus
    enriched.surbl_result = surbl
    enriched.domain_age_days = age
    enriched.registrar = registrar
    enriched.creation_date = created
    enriched.otx_pulse_count = pulses
    enriched.otx_malware_count = malware
    enriched.otx_tags = tags

    return enriched


async def enrich_domains(
    domain_stats: list[DomainStats],
    concurrency: int = 10,
) -> list[EnrichedDomain]:
    """Enrich all domains with threat intel from public sources.

    Uses a semaphore to limit concurrent lookups (avoid overwhelming DNS/HTTP).
    """
    sem = asyncio.Semaphore(concurrency)

    async def _limited(stats: DomainStats) -> EnrichedDomain:
        async with sem:
            return await _enrich_one(stats)

    log.info("enriching_domains", count=len(domain_stats), concurrency=concurrency)
    results = await asyncio.gather(*[_limited(s) for s in domain_stats])
    log.info("enrichment_complete", count=len(results))
    return list(results)
