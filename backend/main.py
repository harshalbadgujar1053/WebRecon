from fastapi import FastAPI, Query
from recon.ip_info import get_ip_info
from recon.whois_lookup import get_whois_info
from recon.dns_records import get_dns_records
from recon.http_headers import get_http_headers
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="WebRecon API",
    description="OSINT-based Website Security Evaluator",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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
    return {
        "target": domain,
        "ip_info": get_ip_info(domain),
        "whois": get_whois_info(domain),
        "dns_records": get_dns_records(domain),
        "http_info": get_http_headers(domain)
    }
