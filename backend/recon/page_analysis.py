import requests
from bs4 import BeautifulSoup

def analyze_page(domain: str):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)

        soup = BeautifulSoup(response.text, "html.parser")

        # --- Social Tags ---
        social_tags = {
            "og:title": None,
            "og:description": None,
            "og:image": None,
            "twitter:card": None,
            "twitter:title": None
        }

        for tag in soup.find_all("meta"):
            prop = tag.get("property") or tag.get("name")
            if prop in social_tags:
                social_tags[prop] = tag.get("content")

        # --- Site Features ---
        features = {
            "has_forms": bool(soup.find("form")),
            "has_login": "login" in response.text.lower(),
            "uses_javascript": "<script" in response.text.lower(),
            "has_iframe": bool(soup.find("iframe"))
        }

        # --- Quality Metrics ---
        quality_metrics = {
            "https": url.startswith("https"),
            "content_length": len(response.text),
            "response_time_ms": response.elapsed.total_seconds() * 1000,
            "status_code": response.status_code
        }

        return {
            "social_tags": social_tags,
            "site_features": features,
            "quality_metrics": quality_metrics
        }

    except Exception as e:
        return {"error": str(e)}
