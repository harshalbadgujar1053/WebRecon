import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# Curated common subdomains (covers majority of public exposure)
SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "beta",
    "blog",
    "ftp",
    "cpanel",
    "webmail",
    "vpn",
    "cdn",
    "static",
    "img",
    "assets",
    "m",
    "mobile",
    "auth",
    "login",
    "dashboard",
    "secure",
    "support",
    "status",
    "apis",
    "rest",
    "graphql",
    "services",
    "backend",
    "service",
    "microservices",
    "gateway"
]


def _resolve_subdomain(fqdn: str):
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        ips = [str(rdata) for rdata in answers]
        return {
            "subdomain": fqdn,
            "ips": ips
        }
    except Exception:
        return None


def subdomain_enum(domain: str):
    """
    DNS-based subdomain enumeration using a curated inline wordlist.
    No external tools or files required.
    """

    discovered = []
    candidates = [f"{sub}.{domain}" for sub in SUBDOMAIN_WORDLIST]

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = [
            executor.submit(_resolve_subdomain, fqdn)
            for fqdn in candidates
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)

    return {
        "method": "dns_bruteforce",
        "wordlist_size": len(SUBDOMAIN_WORDLIST),
        "total_tested": len(candidates),
        "found": discovered,
        "count": len(discovered)
    }
