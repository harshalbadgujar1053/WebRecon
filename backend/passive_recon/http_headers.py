import requests

def get_http_headers(domain: str):
    try:
        url = domain if domain.startswith("http") else f"https://{domain}"
        response = requests.get(url, timeout=10)

        headers = dict(response.headers)

        cookies = []
        for cookie in response.cookies:
            cookies.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httpOnly": cookie.has_nonstandard_attr("HttpOnly")
            })

        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security")
        }

        return {
            "status_code": response.status_code,
            "server": headers.get("Server"),
            "headers": headers,
            "cookies": cookies,
            "security_headers": security_headers
        }

    except Exception as e:
        return {"error": str(e)}
