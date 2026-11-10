
import os
import base64
import requests

from functools import lru_cache
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"

TIMEOUT = 20


def get_headers():

    if not API_KEY:
        raise ValueError(
            "VirusTotal API key missing. Check your .env file."
        )

    return {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }


def extract_report(response):

    attributes = response.get("data", {}).get(
        "attributes", {}
    )

    stats = attributes.get("last_analysis_stats", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation", 0),
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        )
    }


@lru_cache(maxsize=256)
def check_url(url):

    encoded_url = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = f"{BASE_URL}/urls/{encoded_url}"

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "No existing report",
                "message": "URL not found in VirusTotal.",
                "url": url
            }

        response.raise_for_status()

        result = extract_report(response.json())

        result["status"] = "Report available"
        result["url"] = url

        return result

    except requests.exceptions.HTTPError as error:

        return {
            "status": "API error",
            "message": f"HTTP error: {error}",
            "url": url
        }

    except requests.exceptions.RequestException as error:

        return {
            "status": "Connection error",
            "message": str(error),
            "url": url
        }

    except ValueError as error:

        return {
            "status": "Configuration error",
            "message": str(error),
            "url": url
        }


@lru_cache(maxsize=256)
def check_domain(domain):

    endpoint = f"{BASE_URL}/domains/{domain}"

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "No existing report",
                "message": "Domain not found in VirusTotal.",
                "domain": domain
            }

        response.raise_for_status()

        result = extract_report(response.json())

        result["status"] = "Report available"
        result["domain"] = domain

        return result

    except requests.exceptions.HTTPError as error:

        return {
            "status": "API error",
            "message": f"HTTP error: {error}",
            "domain": domain
        }

    except requests.exceptions.RequestException as error:

        return {
            "status": "Connection error",
            "message": str(error),
            "domain": domain
        }

    except ValueError as error:

        return {
            "status": "Configuration error",
            "message": str(error),
            "domain": domain
        }


def analyze_threat_intelligence(urls, domains):

    results = {
        "url_reports": [],
        "domain_reports": []
    }

    # Limit each investigation to four uncached lookups
    # to respect the public API request rate.

    remaining_requests = 4

    for url in list(dict.fromkeys(urls)):

        if remaining_requests <= 0:
            break

        if not check_url.cache_info().currsize:
            pass

        result = check_url(url)

        results["url_reports"].append(result)
        remaining_requests -= 1

    for domain in list(dict.fromkeys(domains)):

        if remaining_requests <= 0:
            break

        result = check_domain(domain)

        results["domain_reports"].append(result)
        remaining_requests -= 1

    return results
