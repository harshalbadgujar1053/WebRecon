from fastapi import FastAPI, Query
from recon.ip_info import get_ip_info
from recon.whois_lookup import get_whois_info
from recon.dns_records import get_dns_records
from recon.http_headers import get_http_headers
from fastapi.middleware.cors import CORSMiddleware
from recon.crawl_rules import get_crawl_rules
from recon.redirects import get_redirect_chain
from recon.security_txt import get_security_txt


app = FastAPI(
    title="WebRecon API",
    description="OSINT-based Website Security Evaluator",
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

@app.get("/ip-info")
def ip_info(domain: str = Query(..., example="example.com")):
    return get_ip_info(domain)

@app.get("/whois")
def whois_info(domain: str = Query(..., example="example.com")):
    return get_whois_info(domain)

@app.get("/dns-records")
def dns_records(domain: str):
    return get_dns_records(domain)

@app.get("/http-info")
def http_info(domain: str):
    return get_http_headers(domain)

@app.get("/scan")
def full_scan(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    return {
        "target": domain,

        "ip_info": get_ip_info(domain),
        "whois": get_whois_info(domain),
        "dns_records": get_dns_records(domain),
        "http_info": get_http_headers(domain),

        "crawl_rules": get_crawl_rules(domain),
        "redirect_chain": get_redirect_chain(domain),
        "security_txt": get_security_txt(domain)
    }
