
import re
import ipaddress
from urllib.parse import urlparse


def analyze_email(parsed_email):

    findings = []
    risk_score = 0

    body = parsed_email.get("body", "").lower()
    urls = parsed_email.get("urls", [])

    # Rule 1: Urgency detection
    urgency_keywords = [
        "urgent",
        "immediately",
        "act now",
        "account suspended",
        "account will be suspended",
        "limited time",
        "within 24 hours"
    ]

    matched_urgency = [
        word for word in urgency_keywords
        if word in body
    ]

    if matched_urgency:

        findings.append({
            "rule": "Urgency Language",
            "severity": "Medium",
            "evidence": matched_urgency,
            "points": 20
        })

        risk_score += 20

    # Rule 2: Credential harvesting indicators
    credential_keywords = [
        "enter your password",
        "verify your password",
        "login credentials",
        "share your password",
        "enter your otp",
        "verify your otp",
        "one-time password"
    ]

    matched_credentials = [
        word for word in credential_keywords
        if word in body
    ]

    if matched_credentials:

        findings.append({
            "rule": "Credential Harvesting Indicators",
            "severity": "High",
            "evidence": matched_credentials,
            "points": 30
        })

        risk_score += 30

    # Rule 3: Account verification language
    verification_keywords = [
        "verify your account",
        "account verification",
        "confirm your account",
        "validate your account"
    ]

    matched_verification = [
        word for word in verification_keywords
        if word in body
    ]

    if matched_verification:

        findings.append({
            "rule": "Account Verification Request",
            "severity": "Medium",
            "evidence": matched_verification,
            "points": 15
        })

        risk_score += 15

    # Rule 4: HTTP URL detection
    for url in urls:

        try:
            parsed_url = urlparse(url)

            if parsed_url.scheme.lower() == "http":

                findings.append({
                    "rule": "Unencrypted HTTP URL",
                    "severity": "Low",
                    "evidence": url,
                    "points": 10
                })

                risk_score += 10

        except ValueError:
            pass

    # Rule 5: IP address used as URL hostname
    for url in urls:

        try:
            hostname = urlparse(url).hostname

            if hostname:

                try:
                    ipaddress.ip_address(hostname)

                    findings.append({
                        "rule": "IP Address Used in URL",
                        "severity": "High",
                        "evidence": url,
                        "points": 25
                    })

                    risk_score += 25

                except ValueError:
                    pass

        except ValueError:
            pass

    # Cap risk score
    risk_score = min(risk_score, 100)

    # Preliminary risk classification
    if risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "message": (
            "No configured indicators detected."
            if not findings
            else "Review the detected indicators and supporting evidence."
        )
    }
