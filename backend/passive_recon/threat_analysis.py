import os
import requests
import tldextract # type: ignore
from datetime import datetime

# ---------------- CONFIG ----------------
VT_API_KEY = "73f0b3704872df08082146575ee00fcb58890e56ba36c5a6cebaf703ce5a15ae"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf"
}

# ---------------- VIRUSTOTAL ----------------
def virustotal_domain_check(domain: str):
    if not VT_API_KEY:
        return {
            "enabled": False,
            "message": "VirusTotal API key not configured"
        }

    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(
            VT_DOMAIN_URL.format(domain),
            headers=headers,
            timeout=10
        )

        if r.status_code != 200:
            return {
                "enabled": True,
                "status": "error",
                "message": "VirusTotal API request failed"
            }

        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "enabled": True,
            "source": "VirusTotal",
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data["data"]["attributes"].get("reputation", 0)
        }

    except Exception as e:
        return {
            "enabled": True,
            "status": "error",
            "message": str(e)
        }

# ---------------- HEURISTIC ANALYSIS ----------------
def threat_analysis(domain: str, whois_data: dict, tls_data: dict, dns_data: dict):
    findings = []
    risk = "Low"

    # Domain age
    try:
        created = whois_data.get("creation_date")
        if created:
            if isinstance(created, list):
                created = created[0]
            age_days = (datetime.utcnow() - created.replace(tzinfo=None)).days
            if age_days < 180:
                findings.append("Domain is newly registered (phishing risk)")
                risk = "Medium"
    except Exception:
        pass

    # TLD reputation
    ext = tldextract.extract(domain)
    if ext.suffix in SUSPICIOUS_TLDS:
        findings.append(f"Suspicious TLD detected: .{ext.suffix}")
        risk = "Medium"

    # Email security (phishing indicator)
    txt = dns_data.get("TXT", [])
    if not any("dmarc" in t.lower() for t in txt):
        findings.append("DMARC not configured (email phishing risk)")
        risk = "Medium"

    # TLS security
    if tls_data and tls_data.get("expired"):
        findings.append("Expired TLS certificate")
        risk = "High"

    if not findings:
        findings.append("No obvious malicious indicators detected")

    # VirusTotal enrichment
    vt_result = virustotal_domain_check(domain)

    if vt_result.get("enabled") and vt_result.get("malicious", 0) > 0:
        findings.append("VirusTotal engines flagged this domain as malicious")
        risk = "High"

    return {
        "risk_level": risk,
        "findings": findings,
        "virustotal": vt_result,
        "external_reports": {
            "virustotal": f"https://www.virustotal.com/gui/domain/{domain}",
            "netcraft": f"https://sitereport.netcraft.com/?url=http://{domain}",
            "crt_sh": f"https://crt.sh/?q={domain}"
        }
    }
