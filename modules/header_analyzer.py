
import re
from email.utils import parseaddr


def extract_domain(value):
    """Extract domain from an email address."""

    if not value:
        return ""

    address = parseaddr(str(value))[1]

    if "@" not in address:
        return ""

    return address.rsplit("@", 1)[1].lower()


def analyze_headers(parsed_email):

    headers = parsed_email.get("headers", {})

    # Extract important headers
    from_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")
    message_id = headers.get("Message-ID", "")
    authentication = headers.get("Authentication-Results", "")

    findings = []

    # Extract sender domains
    from_domain = extract_domain(from_header)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    # Check From and Reply-To mismatch
    if reply_domain and from_domain and reply_domain != from_domain:

        findings.append({
            "rule": "From and Reply-To Domain Mismatch",
            "severity": "Medium",
            "evidence": f"From: {from_domain}, Reply-To: {reply_domain}"
        })

    # Check From and Return-Path mismatch
    if return_domain and from_domain and return_domain != from_domain:

        findings.append({
            "rule": "From and Return-Path Domain Mismatch",
            "severity": "Low",
            "evidence": f"From: {from_domain}, Return-Path: {return_domain}"
        })

    # Check Authentication-Results
    auth_results = {}

    for protocol in ["spf", "dkim", "dmarc"]:

        match = re.search(
            rf'\b{protocol}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b',
            authentication,
            re.IGNORECASE
        )

        if match:
            status = match.group(1).lower()
            auth_results[protocol] = status

            if status in ["fail", "softfail"]:

                findings.append({
                    "rule": f"{protocol.upper()} Authentication Failure",
                    "severity": "High",
                    "evidence": f"{protocol.upper()} reported result: {status}"
                })

        else:
            auth_results[protocol] = "Not reported"

    # Check missing authentication results
    if not authentication:

        findings.append({
            "rule": "Authentication-Results Header Missing",
            "severity": "Informational",
            "evidence": "No Authentication-Results header found"
        })

    # Count available Received headers
    received = headers.get("Received", "")

    if isinstance(received, list):
        received_count = len(received)
    elif received:
        received_count = 1
    else:
        received_count = 0

    return {
        "from_domain": from_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_domain,
        "return_path": return_path,
        "return_path_domain": return_domain,
        "message_id": message_id,
        "authentication_results": auth_results,
        "received_header_count": received_count,
        "findings": findings
    }
