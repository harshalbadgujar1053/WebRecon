import requests
from builtwith import builtwith

def detect_firewall(domain: str):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)
        headers = response.headers

        waf_signatures = {
            "cloudflare": "cloudflare",
            "akamai": "akamai",
            "imperva": "incapsula",
            "sucuri": "sucuri"
        }

        for name, signature in waf_signatures.items():
            for header in headers.values():
                if signature.lower() in header.lower():
                    return {"waf_detected": True, "provider": name}

        return {"waf_detected": False}

    except Exception as e:
        return {"error": str(e)}

def get_tech_stack(domain: str):
    try:
        return builtwith(f"https://{domain}")
    except Exception as e:
        return {"error": str(e)}

def get_archive_history(domain: str):
    try:
        url = f"https://archive.org/wayback/available?url={domain}"
        response = requests.get(url)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def get_global_ranking(domain: str):
    return {
        "note": "Traffic ranking requires third-party APIs (e.g., SimilarWeb)",
        "status": "Not available in free tier"
    }
