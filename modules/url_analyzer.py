
import socket
import ipaddress
from urllib.parse import urlparse


PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32")
]


def classify_ip(ip):

    if any(ip in network for network in PRIVATE_NETWORKS):
        return "Private IP address"

    if any(ip in network for network in DOCUMENTATION_NETWORKS):
        return "Documentation IP address"

    if ip.is_loopback:
        return "Loopback IP address"

    if ip.is_link_local:
        return "Link-local IP address"

    if ip.is_multicast:
        return "Multicast IP address"

    if ip.is_reserved or ip.is_unspecified:
        return "Reserved or unspecified IP address"

    if ip.is_global:
        return "Public IP address"

    return "Non-global IP address"


def analyze_urls(urls):

    results = []

    for url in urls:

        parsed = urlparse(url)

        hostname = parsed.hostname
        scheme = parsed.scheme.lower()

        findings = []
        resolved_ips = []

        if scheme == "http":
            findings.append("Unencrypted HTTP connection")

        if not hostname:
            findings.append("Invalid or missing hostname")

        else:

            try:
                ip = ipaddress.ip_address(hostname)

                findings.append("IP address used as URL hostname")
                findings.append(classify_ip(ip))

            except ValueError:

                try:
                    addresses = socket.getaddrinfo(
                        hostname,
                        None,
                        type=socket.SOCK_STREAM
                    )

                    resolved_ips = sorted({
                        item[4][0] for item in addresses
                    })

                except socket.gaierror:
                    findings.append("DNS resolution failed")

        if parsed.username or parsed.password:
            findings.append("URL contains embedded credentials")

        if hostname and hostname.startswith("xn--"):
            findings.append("Punycode hostname detected")

        results.append({
            "url": url,
            "hostname": hostname or "",
            "scheme": scheme,
            "resolved_ips": resolved_ips,
            "findings": findings,
            "status": (
                "Indicators found"
                if findings
                else "No configured indicators found"
            )
        })

    return results
