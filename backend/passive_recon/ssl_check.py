"""
ssl_check.py — SSL certificate quick-check utility.
Complements tls_analysis.py with a simpler pass/fail interface
suitable for dashboard-level security indicators.
"""
import ssl
import socket
from datetime import datetime


def ssl_check(domain: str) -> dict:
    """
    Quick SSL health check: validates cert, expiry, and hostname match.
    Returns structured result with status and key details.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher, _, key_bits = ssock.cipher()

        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")

        fmt = "%b %d %H:%M:%S %Y %Z"
        expiry = datetime.strptime(not_after_str, fmt) if not_after_str else None
        issued = datetime.strptime(not_before_str, fmt) if not_before_str else None
        now = datetime.utcnow()

        days_remaining = (expiry - now).days if expiry else None
        expired = expiry < now if expiry else None

        warnings = []
        if expired:
            warnings.append("Certificate is expired")
        elif days_remaining is not None and days_remaining < 30:
            warnings.append(f"Certificate expires in {days_remaining} days — renew soon")
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            warnings.append(f"Weak protocol in use: {protocol}")

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        return {
            "status": "completed",
            "valid": not expired,
            "expired": expired,
            "days_remaining": days_remaining,
            "issued_on": not_before_str,
            "expires_on": not_after_str,
            "common_name": subject.get("commonName"),
            "organization": subject.get("organizationName"),
            "issuer": issuer.get("organizationName"),
            "protocol": protocol,
            "cipher": cipher,
            "key_bits": key_bits,
            "warnings": warnings
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "status": "invalid",
            "valid": False,
            "error": f"Certificate verification failed: {str(e)}",
            "warnings": ["SSL certificate could not be verified"]
        }
    except socket.timeout:
        return {"status": "timeout", "valid": None, "error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"status": "blocked", "valid": None, "error": "Port 443 refused — HTTPS may not be enabled"}
    except Exception as e:
        return {"status": "error", "valid": None, "error": str(e)}