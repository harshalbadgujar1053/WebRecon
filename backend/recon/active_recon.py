import socket
import subprocess
import platform
import requests

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

def scan_open_ports(domain: str):
    open_ports = []

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            sock.close()

            if result == 0:
                open_ports.append({
                    "port": port,
                    "service": service,
                    "status": "open"
                })

        except Exception:
            continue

    return open_ports
def traceroute(domain: str):
    try:
        system = platform.system().lower()

        if system == "windows":
            command = ["tracert", domain]
        else:
            command = ["traceroute", domain]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )

        return {
            "executed": True,
            "output": result.stdout
        }

    except Exception as e:
        return {
            "executed": False,
            "error": str(e)
        }

def block_detection(domain: str):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)

        blocked_codes = [403, 406, 429]

        blocked = response.status_code in blocked_codes

        return {
            "blocked": blocked,
            "status_code": response.status_code,
            "reason": "Possible WAF or rate limiting" if blocked else "No blocking detected"
        }

    except Exception as e:
        return {
            "blocked": True,
            "error": str(e)
        }
