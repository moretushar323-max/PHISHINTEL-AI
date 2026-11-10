
import re
import ipaddress

from email import message_from_string
from email.policy import default
from email.utils import getaddresses
from urllib.parse import urlparse


def parse_email(raw_email):

    # 1. Parse raw email
    msg = message_from_string(raw_email, policy=default)

    # 2. Extract sender
    sender_addresses = getaddresses(msg.get_all("From", []))

    sender = next(
        (address for _, address in sender_addresses if address),
        ""
    )

    # 3. Extract recipient
    recipient_addresses = getaddresses(
        msg.get_all("To", [])
    )

    recipient = next(
        (address for _, address in recipient_addresses if address),
        ""
    )

    # 4. Extract email body
    body_parts = []

    if msg.is_multipart():

        for part in msg.walk():

            if part.get_content_type() == "text/plain":

                try:
                    content = part.get_content()

                    if content:
                        body_parts.append(content)

                except Exception:
                    pass

    else:

        try:
            body_parts.append(msg.get_content())

        except Exception:
            body_parts.append(str(msg.get_payload()))

    body = "\n".join(body_parts)

    # 5. Extract URLs
    url_pattern = r'https?://[^\s<>"\']+'

    extracted_urls = re.findall(url_pattern, body)

    # Remove common trailing punctuation
    urls = sorted({
        url.rstrip(".,;:!?)]}")
        for url in extracted_urls
    })

    # 6. Extract domains from URLs
    domains = set()

    for url in urls:

        try:
            domain = urlparse(url).hostname

            if domain:
                domains.add(domain.lower())

        except ValueError:
            pass

    # 7. Extract valid IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    possible_ips = re.findall(ip_pattern, raw_email)

    valid_ips = set()

    for ip in possible_ips:

        try:
            ipaddress.ip_address(ip)
            valid_ips.add(ip)

        except ValueError:
            pass

    # 8. Extract email headers
    headers = {
        key: str(value)
        for key, value in msg.items()
    }

    # 9. Return structured email information
    return {

        "sender": sender,

        "recipient": recipient,

        "subject": str(msg.get("Subject", "")),

        "date": str(msg.get("Date", "")),

        "headers": headers,

        "body": body,

        "urls": urls,

        "domains": sorted(domains),

        "ip_addresses": sorted(valid_ips)

    }
