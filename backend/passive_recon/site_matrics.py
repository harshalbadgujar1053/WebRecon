import requests

def get_site_metrics(domain: str):
    """
    Returns basic site health/performance metrics.
    NOTE: This file was renamed from site_matrics.py → site_metrics.py
    Update the import in main.py accordingly.
    """
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)
        headers = response.headers

        return {
            "status": "completed",
            "server_status":  response.status_code,
            "hsts_enabled":   "Strict-Transport-Security" in headers,
            "https":          url.startswith("https"),
            "server":         headers.get("Server"),
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "content_length": len(response.content)
        }

    except requests.exceptions.ConnectionError:
        return {"status": "blocked", "message": "Connection refused or host unreachable"}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "message": "Request timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}