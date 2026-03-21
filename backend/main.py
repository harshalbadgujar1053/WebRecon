from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
import traceback

from passive_recon.ip_info import get_ip_info
from passive_recon.whois_lookup import get_whois_info
from passive_recon.dns_records import get_dns_records
from passive_recon.http_headers import get_http_headers
from passive_recon.crawl_rules import get_crawl_rules
from passive_recon.redirects import get_redirect_chain
from passive_recon.security_txt import get_security_txt
from passive_recon.page_analysis import analyze_page
from passive_recon.dns_security import check_dnssec, get_email_security
from passive_recon.infra_intel import detect_firewall, get_tech_stack, get_archive_history, get_global_ranking
from passive_recon.tls_analysis import get_ssl_chain, get_tls_ciphers, tls_security_config, tls_handshake_simulation
from active_recon.port_scan import port_scan
from active_recon.subdomain_enum import subdomain_enum
from active_recon.dir_enum import dir_enum
from active_recon.api_discovery import api_discovery
from passive_recon.threat_analysis import threat_analysis

app = FastAPI(
    title="SyknetScope",
    description="Website Security Analyzer",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  TIMEOUT WRAPPER
#  Runs any function with a hard time limit.
#  Returns {"status":"timeout"} if it exceeds
#  the limit instead of hanging forever.
# ─────────────────────────────────────────────
_executor = ThreadPoolExecutor(max_workers=20)

def safe_call(fn, *args, timeout=12, label="module"):
    """
    Call fn(*args) with a hard timeout.
    Returns structured error dict on failure/timeout
    instead of crashing or hanging the whole scan.
    """
    try:
        future = _executor.submit(fn, *args)
        return future.result(timeout=timeout)
    except FuturesTimeout:
        return {"status": "timeout", "error": f"{label} timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/")
def home():
    return {"message": "SyknetScope backend is running 🚀"}


@app.get("/scan")
def full_scan(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    # Run shared data once — used by multiple modules
    whois_data  = safe_call(get_whois_info,  domain, timeout=10, label="whois")
    ssl_chain   = safe_call(get_ssl_chain,   domain, timeout=8,  label="ssl_chain")
    dns_records = safe_call(get_dns_records, domain, timeout=8,  label="dns_records")

    return {
        "target": domain,

        # Passive OSINT
        "ip_info":        safe_call(get_ip_info,         domain, timeout=8,  label="ip_info"),
        "whois":          whois_data,
        "dns_records":    dns_records,
        "http_info":      safe_call(get_http_headers,    domain, timeout=10, label="http_headers"),
        "crawl_rules":    safe_call(get_crawl_rules,     domain, timeout=6,  label="crawl_rules"),
        "redirect_chain": safe_call(get_redirect_chain,  domain, timeout=8,  label="redirects"),
        "security_txt":   safe_call(get_security_txt,    domain, timeout=6,  label="security_txt"),
        "page_analysis":  safe_call(analyze_page,        domain, timeout=12, label="page_analysis"),

        # DNS & Infra
        "dns_security":        safe_call(check_dnssec,       domain, timeout=6,  label="dnssec"),
        "email_configuration": safe_call(get_email_security, domain, timeout=8,  label="email_security"),
        "firewall_detection":  safe_call(detect_firewall,    domain, timeout=10, label="firewall"),
        "tech_stack":          safe_call(get_tech_stack,     domain, timeout=15, label="tech_stack"),
        "archive_history":     safe_call(get_archive_history,domain, timeout=8,  label="archive"),
        "global_ranking":      safe_call(get_global_ranking, domain, timeout=5,  label="ranking"),

        # TLS
        "ssl_chain":          ssl_chain,
        "tls_cipher_suites":  safe_call(get_tls_ciphers,          domain, timeout=8,  label="tls_ciphers"),
        "tls_security_config": safe_call(tls_security_config,     domain, timeout=10, label="tls_config"),
        "tls_handshake":      safe_call(tls_handshake_simulation,  domain, timeout=8,  label="tls_handshake"),

        # Threat
        "threat_analysis": safe_call(
            threat_analysis, domain, whois_data, ssl_chain, dns_records,
            timeout=15, label="threat_analysis"
        ),
    }


@app.get("/active-scan")
def active_scan(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    return {
        "target":         domain,
        "port_scan":      safe_call(port_scan,      domain, timeout=60, label="port_scan"),
        "subdomain_enum": safe_call(subdomain_enum, domain, timeout=30, label="subdomain_enum"),
        "directory_enum": safe_call(dir_enum,       domain, timeout=40, label="dir_enum"),
        "api_discovery":  safe_call(api_discovery,  domain, timeout=20, label="api_discovery"),
    }