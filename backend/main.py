from fastapi import FastAPI, Query
from recon.ip_info import get_ip_info
from recon.whois_lookup import get_whois_info

app = FastAPI(
    title="WebRecon API",
    description="OSINT-based Website Security Evaluator",
    version="1.0"
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
