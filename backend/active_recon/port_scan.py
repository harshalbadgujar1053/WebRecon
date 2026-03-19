import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Port → (Protocol, Service Name)
PORT_SERVICES = {
    1: ("TCP/UDP", "tcpmux"),
    5: ("TCP/UDP", "rje"),
    7: ("TCP/UDP", "echo"),
    9: ("TCP/UDP", "discard"),
    11: ("TCP/UDP", "systat"),
    13: ("TCP/UDP", "daytime"),
    17: ("TCP/UDP", "qotd"),
    18: ("TCP/UDP", "msp"),
    19: ("TCP/UDP", "chargen"),
    20: ("TCP/UDP", "ftp-data"),
    21: ("TCP/UDP", "ftp"),
    22: ("TCP/UDP", "ssh"),
    23: ("TCP/UDP", "telnet"),
    25: ("TCP/UDP", "smtp"),
    37: ("TCP/UDP", "time"),
    39: ("TCP/UDP", "rlp"),
    42: ("TCP/UDP", "nameserver"),
    43: ("TCP/UDP", "nicname"),
    49: ("TCP/UDP", "tacacs"),
    50: ("TCP/UDP", "re-mail-ck"),
    53: ("TCP/UDP", "domain"),
    63: ("TCP/UDP", "whois++"),
    67: ("TCP/UDP", "bootps"),
    68: ("TCP/UDP", "bootpc"),
    69: ("TCP/UDP", "tftp"),
    70: ("TCP/UDP", "gopher"),
    79: ("TCP/UDP", "finger"),
    80: ("TCP/UDP", "http"),
    88: ("TCP/UDP", "kerberos"),
    102: ("TCP", "iso-tsap"),
    109: ("TCP/UDP", "pop2"),
    110: ("TCP/UDP", "pop3"),
    111: ("TCP/UDP", "sunrpc"),
    113: ("TCP/UDP", "auth"),
    119: ("TCP/UDP", "nntp"),
    123: ("TCP/UDP", "ntp"),
    137: ("TCP/UDP", "netbios-ns"),
    138: ("TCP/UDP", "netbios-dgm"),
    139: ("TCP/UDP", "netbios-ssn"),
    143: ("TCP/UDP", "imap"),
    161: ("TCP/UDP", "snmp"),
    179: ("TCP/UDP", "bgp"),
    194: ("TCP/UDP", "irc"),
    389: ("TCP/UDP", "ldap"),
    443: ("TCP/UDP", "https"),
    445: ("TCP/UDP", "microsoft-ds"),
    465: ("TCP", "smtps"),
    500: ("TCP/UDP", "isakmp"),
    512: ("TCP", "exec"),
    513: ("TCP", "login"),
    514: ("TCP", "shell"),
    515: ("TCP/UDP", "printer"),
    520: ("TCP", "efs"),
    523: ("TCP/UDP", "ibm-db2"),
    631: ("TCP/UDP", "ipp"),
    636: ("TCP/UDP", "ldaps"),
    873: ("TCP/UDP", "rsync"),
    989: ("TCP", "ftps-data"),
    990: ("TCP", "ftps"),
    993: ("TCP/UDP", "imaps"),
    995: ("TCP/UDP", "pop3s"),

    # Explicitly requested extra ports
    3306: ("TCP", "mysql"),
    3389: ("TCP", "rdp"),
    8080: ("TCP", "http-alt")
}


def _scan_port(domain, port, timeout=0.3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((domain, port)) == 0:
            return port
        sock.close()
    except Exception:
        return None
    return None


def port_scan(domain: str):
    """
    Scan ports 1–1024 + selected high-value ports
    """

    ports_to_scan = list(range(1, 1025)) + [3306, 3389, 8080]
    open_ports = []

    with ThreadPoolExecutor(max_workers=300) as executor:
        futures = [executor.submit(_scan_port, domain, p) for p in ports_to_scan]

        for future in as_completed(futures):
            port = future.result()
            if port:
                protocol, service = PORT_SERVICES.get(
                    port, ("TCP", "unknown")
                )
                open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "service": service
                })

    open_ports.sort(key=lambda x: x["port"])

    return {
        "scan_range": "1-1024 (+3306, 3389, 8080)",
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }