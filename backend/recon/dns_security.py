import dns.resolver

def check_dnssec(domain: str):
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        return {"dnssec_enabled": True}
    except Exception:
        return {"dnssec_enabled": False}

def get_email_security(domain: str):
    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None
    }

    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for record in txt_records:
            text = record.to_text()

            if "v=spf1" in text:
                result["spf"] = text

    except Exception:
        pass

    try:
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = dns.resolver.resolve(dmarc_domain, "TXT")
        for record in txt_records:
            result["dmarc"] = record.to_text()
    except Exception:
        pass

    # DKIM is selector-based → we just indicate unknown
    result["dkim"] = "Selector-based (manual verification required)"

    return result
