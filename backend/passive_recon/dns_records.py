import dns.resolver

def resolve_record(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def get_dns_records(domain: str):
    return {
        "A": resolve_record(domain, "A"),
        "AAAA": resolve_record(domain, "AAAA"),
        "MX": resolve_record(domain, "MX"),
        "NS": resolve_record(domain, "NS"),
        "CNAME": resolve_record(domain, "CNAME"),
        "TXT": resolve_record(domain, "TXT"),
    }
