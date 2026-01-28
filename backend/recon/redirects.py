import requests

def get_redirect_chain(domain: str):
    try:
        url = domain if domain.startswith("http") else f"http://{domain}"
        response = requests.get(url, allow_redirects=True, timeout=10)

        chain = []
        for r in response.history:
            chain.append({
                "url": r.url,
                "status_code": r.status_code
            })

        chain.append({
            "url": response.url,
            "status_code": response.status_code
        })

        return chain

    except Exception as e:
        return {"error": str(e)}
