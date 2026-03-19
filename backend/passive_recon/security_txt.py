import requests

def get_security_txt(domain: str):
    try:
        url = f"https://{domain}/.well-known/security.txt"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return {
                "exists": True,
                "content": response.text
            }

        return {"exists": False}

    except Exception as e:
        return {"error": str(e)}
