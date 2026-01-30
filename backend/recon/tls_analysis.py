import ssl
import socket
from datetime import datetime

def get_ssl_chain(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter"),
            "expired": datetime.utcnow() > datetime.strptime(
                cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z"
            )
        }

    except Exception as e:
        return {"error": str(e)}

def get_tls_ciphers(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()

        return {
            "cipher_suite": cipher[0],
            "protocol": cipher[1],
            "key_size": cipher[2]
        }

    except Exception as e:
        return {"error": str(e)}

def tls_security_config(domain: str):
    insecure_protocols = []

    protocols = {
        "SSLv3": ssl.PROTOCOL_SSLv3 if hasattr(ssl, "PROTOCOL_SSLv3") else None,
        "TLSv1": ssl.PROTOCOL_TLSv1,
        "TLSv1_1": ssl.PROTOCOL_TLSv1_1
    }

    for name, proto in protocols.items():
        if proto is None:
            continue
        try:
            context = ssl.SSLContext(proto)
            with socket.create_connection((domain, 443), timeout=3) as sock:
                context.wrap_socket(sock, server_hostname=domain)
            insecure_protocols.append(name)
        except Exception:
            pass

    return {
        "weak_protocols_supported": insecure_protocols,
        "secure_by_default": len(insecure_protocols) == 0
    }
def tls_handshake_simulation(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return {
                    "handshake_successful": True,
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()
                }

    except Exception as e:
        return {
            "handshake_successful": False,
            "error": str(e)
        }
