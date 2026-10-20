import ipaddress
import re

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)

PRIVATE_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # CGNAT
        "169.254.0.0/16",  # link-local
        "127.0.0.0/8",  # loopback
    )
]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


def detect_type(indicator: str) -> str:
    indicator = indicator.strip()

    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(indicator):
            return hash_type

    if indicator.startswith(("http://", "https://")):
        return "url"

    if DOMAIN_PATTERN.match(indicator):
        return "domain"

    return "unknown"
