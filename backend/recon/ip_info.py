import socket
import requests

def get_ip_info(domain: str):
    try:
        ip_address = socket.gethostbyname(domain)

        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()

        return {
            "ip": ip_address,
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org"),
            "location": data.get("loc")
        }

    except Exception as e:
        return {"error": str(e)}
