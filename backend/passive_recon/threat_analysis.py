import os
import requests
import tldextract  # type: ignore
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

VT_API_KEY    = os.environ.get("VT_API_KEY", "")
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf"}


def virustotal_domain_check(domain: str):
    if not VT_API_KEY:
        return {"enabled": False, "message": "Set VT_API_KEY environment variable."}
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(VT_DOMAIN_URL.format(domain), headers=headers, timeout=10)
        if r.status_code == 401:
            return {"enabled": True, "status": "error", "message": "Invalid VirusTotal API key"}
        if r.status_code != 200:
            return {"enabled": True, "status": "error", "message": f"VirusTotal returned HTTP {r.status_code}"}
        data  = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "enabled": True, "source": "VirusTotal",
            "harmless":   stats.get("harmless", 0),
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data["data"]["attributes"].get("reputation", 0)
        }
    except Exception as e:
        return {"enabled": True, "status": "error", "message": str(e)}


def threat_analysis(domain: str, whois_data: dict, tls_data: dict, dns_data: dict):
    findings = []
    risk = "Low"

    # Domain age
    try:
        created = whois_data.get("creation_date")
        if created:
            if isinstance(created, list): created = created[0]
            if isinstance(created, str):
                from dateutil import parser as dp
                created = dp.parse(created)
            if created:
                age_days = (datetime.utcnow() - created.replace(tzinfo=None)).days
                if age_days < 180:
                    findings.append(f"Domain is newly registered ({age_days} days old) — phishing risk")
                    risk = "Medium"
    except Exception:
        pass

    # Suspicious TLD
    try:
        ext = tldextract.extract(domain)
        if ext.suffix in SUSPICIOUS_TLDS:
            findings.append(f"Suspicious TLD detected: .{ext.suffix}")
            if risk == "Low": risk = "Medium"
    except Exception:
        pass

    # DMARC — FIX: query _dmarc.<domain> directly, not root TXT records
    dmarc_found = False
    try:
        import dns.resolver
        for rec in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in rec.to_text().lower():
                dmarc_found = True
                break
    except Exception:
        pass

    if not dmarc_found:
        findings.append("DMARC not configured — email spoofing/phishing risk")
        if risk == "Low": risk = "Medium"

    # SPF
    try:
        txt_records = dns_data.get("TXT", [])
        if not any("v=spf1" in t.lower() for t in txt_records):
            findings.append("SPF record not configured — email spoofing risk")
    except Exception:
        pass

    # TLS expiry
    try:
        if tls_data and tls_data.get("expired"):
            findings.append("TLS certificate is expired")
            risk = "High"
    except Exception:
        pass

    if not findings:
        findings.append("No obvious malicious indicators detected")

    vt_result = virustotal_domain_check(domain)
    if vt_result.get("enabled") and vt_result.get("malicious", 0) > 0:
        findings.append(f"VirusTotal: {vt_result['malicious']} engine(s) flagged this domain as malicious")
        risk = "High"

    return {
        "risk_level": risk,
        "findings":   findings,
        "virustotal": vt_result,
        "external_reports": {
            "virustotal": f"https://www.virustotal.com/gui/domain/{domain}",
            "netcraft":   f"https://sitereport.netcraft.com/?url=http://{domain}",
            "crt_sh":     f"https://crt.sh/?q={domain}"
        }
    }