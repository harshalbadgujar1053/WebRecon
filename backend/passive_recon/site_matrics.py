import requests

def get_site_metrics(domain: str):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)

        headers = response.headers

        return {
            "server_status": response.status_code,
            "hsts_enabled": "Strict-Transport-Security" in headers,
            "https": url.startswith("https"),
            "server": headers.get("Server")
        }

    except Exception as e:
        return {"error": str(e)}
