from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

@app.get("/")
def home():
    return {"message": "WebRecon backend is running 🚀"}

@app.get("/scan")
def full_scan(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    return {
        "target": domain,

        # Passive OSINT
        "ip_info": get_ip_info(domain),
        "whois": get_whois_info(domain),
        "dns_records": get_dns_records(domain),
        "http_info": get_http_headers(domain),
        "crawl_rules": get_crawl_rules(domain),
        "redirect_chain": get_redirect_chain(domain),
        "security_txt": get_security_txt(domain),
        "page_analysis": analyze_page(domain),

        # DNS & Infra Intelligence
        "dns_security": check_dnssec(domain),
        "email_configuration": get_email_security(domain),
        "firewall_detection": detect_firewall(domain),
        "tech_stack": get_tech_stack(domain),
        "archive_history": get_archive_history(domain),
        "global_ranking": get_global_ranking(domain),

        # TLS Analysis
        "ssl_chain": get_ssl_chain(domain),
        "tls_cipher_suites": get_tls_ciphers(domain),
        "tls_security_config": tls_security_config(domain),
        "tls_handshake": tls_handshake_simulation(domain),
        "threat_analysis": threat_analysis(domain,get_whois_info(domain),get_ssl_chain(domain),get_dns_records(domain)
)

    }

@app.get("/active-scan")
def active_scan(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    return {
        "target": domain,
        "active_recon": {
            "port_scan": port_scan(domain),
            "subdomain_enum": subdomain_enum(domain),
            "directory_enum": dir_enum(domain),
            "api_discovery": api_discovery(domain)
        }
    }

