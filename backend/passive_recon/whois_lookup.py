import whois

def _fmt_date(val):
    """Safely format whois date fields — handles datetime, list of datetimes, strings."""
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0]
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    except AttributeError:
        return str(val)

def get_whois_info(domain: str):
    try:
        w = whois.whois(domain)

        domain_name = w.domain_name
        if isinstance(domain_name, list):
            domain_name = domain_name[0]

        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = sorted(set(s.upper() for s in name_servers))

        status = w.status
        if isinstance(status, list):
            status = status[0] if status else None

        return {
            "domain_name":     domain_name,
            "registrar":       w.registrar,
            "creation_date":   _fmt_date(w.creation_date),
            "expiration_date": _fmt_date(w.expiration_date),
            "updated_date":    _fmt_date(w.updated_date),
            "name_servers":    name_servers,
            "status":          status
        }

    except Exception as e:
        return {"error": str(e)}