"""
DNS record enumeration phase.

Queries all DNS record types for intelligence about the target's
infrastructure: mail servers, name servers, TXT records (SPF/DKIM/DMARC),
CNAMEs, and other useful indicators.
"""

import asyncio
from mantis.engage.phases import Phase

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class DNSEnumerator:
    """Query DNS records for a domain."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR", "CAA"]

    async def enumerate(self, domain: str) -> dict:
        if not HAS_DNS:
            return {"error": "dnspython not installed. pip install dnspython"}

        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        loop = asyncio.get_event_loop()
        for rtype in self.RECORD_TYPES:
            try:
                answers = await loop.run_in_executor(
                    None, lambda rt=rtype: resolver.resolve(domain, rt)
                )
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.exception.DNSException):
                continue

        # Extract useful info from TXT records
        txt_records = records.get("TXT", [])
        spf = [r for r in txt_records if "v=spf1" in r]
        dmarc_domain = f"_dmarc.{domain}"
        try:
            dmarc_answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(dmarc_domain, "TXT")
            )
            records["DMARC"] = [str(r) for r in dmarc_answers]
        except Exception:
            pass

        return records


class DNSEnumPhase(Phase):
    """Phase: enumerate DNS records for the target domain."""

    async def execute(self, context) -> dict:
        domain = self.config.target
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0]

        enumerator = DNSEnumerator()
        records = await enumerator.enumerate(domain)

        total = sum(len(v) for v in records.values() if isinstance(v, list))
        print(f"    DNS records found: {total} across {len(records)} types")
        return {"dns_records": records}
