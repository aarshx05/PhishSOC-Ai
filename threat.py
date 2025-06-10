import requests
import whois
import ssl
import socket

def check_openphish(url: str) -> dict:
    """Checks if a given URL is in the OpenPhish phishing database."""
    try:
        response = requests.get("https://openphish.com/feed.txt")
        response.raise_for_status()

        phishing_urls = response.text.splitlines()
        found = url in phishing_urls
        return {
            "status": "found" if found else "not found",
            "details": "This URL is listed as a phishing site by OpenPhish." if found else "No record found."
        }
    except requests.exceptions.RequestException as e:
        return {"status": "error", "details": str(e)}


def check_abuse_ch(url: str) -> dict:
    """Checks if a URL is reported in Abuse.ch's URLhaus database."""
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        response = requests.post(endpoint, data={"url": url})
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "malicious":
            return {
                "status": "malicious",
                "details": {
                    "threat_type": data.get("threat"),
                    "malware": data.get("malware_printable"),
                    "reference": data.get("urlhaus_reference")
                }
            }
        return {"status": "clean", "details": "No threats detected."}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "details": str(e)}


def check_virustotal(url: str, api_key: str) -> dict:
    """Checks the reputation of a URL using VirusTotal API."""
    headers = {"x-apikey": api_key}
    data = {"url": url}

    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        # Retrieve analysis results
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=headers)
        report_response.raise_for_status()
        report_data = report_response.json()

        stats = report_data["data"]["attributes"]["stats"]
        malicious_count = stats["malicious"]

        # If any vendor flagged it as malicious, mark as malicious
        is_flagged = malicious_count > 0

        return {
            "status": "malicious" if is_flagged else "safe",
            "details": {
                "malicious_count": malicious_count,
                "reference": f"https://www.virustotal.com/gui/url/{analysis_id}"
            } if is_flagged else "No issues found."
        }
    except requests.exceptions.RequestException as e:
        return {"status": "error", "details": str(e)}

def get_whois_info(domain: str) -> dict:
    """Retrieves WHOIS information for a given domain."""
    try:
        domain_info = whois.whois(domain)

        if not domain_info.domain_name:
            return {
                "status": "info",
                "details": f"{domain} does not have a public WHOIS record. Likely a cloud subdomain."
            }

        return {
            "status": "success",
            "details": {
                "domain": domain,
                "registrar": domain_info.registrar,
                "creation_date": str(domain_info.creation_date),
                "expiration_date": str(domain_info.expiration_date),
                "name_servers": domain_info.name_servers,
            }
        }
    except Exception:
        return {
            "status": "info",
            "details": f"{domain} does not have a public WHOIS record. Likely a cloud subdomain."
        }

def check_ssl_info(domain: str) -> dict:
    """Checks the SSL certificate details of a given domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "status": "secure",
            "details": {
                "issuer": issuer.get("organizationName", "Unknown"),
                "valid_from": cert.get("notBefore", "N/A"),
                "valid_until": cert.get("notAfter", "N/A"),
            }
        }
    except socket.gaierror:
        return {"status": "error", "details": "DNS resolution failed (Domain may not exist)."}
    except ssl.SSLError:
        return {"status": "untrusted", "details": "Self-signed or expired certificate detected."}
    except Exception as e:
        return {"status": "error", "details": f"SSL error: {str(e)}"}


def check_url_reputation(url: str, vt_api_key: str) -> dict:
    """Checks the reputation of a URL using OpenPhish, Abuse.ch, and VirusTotal."""
    results = {
        "OpenPhish": check_openphish(url),
        "Abuse.ch": check_abuse_ch(url),
        "VirusTotal": check_virustotal(url, vt_api_key),
        "WHOIS": get_whois_info(url),
        "SSL Certificate": check_ssl_info(url)
    }
    return results


def clean_url(url: str) -> str:
    """Removes the 'http://' or 'https://' from the URL."""
    if url.startswith("http://"):
        return url[len("http://"):]
    elif url.startswith("https://"):
        return url[len("https://"):]
    return url


def analyze_urls_from_file(filename: str, vt_api_key: str):
    """Reads URLs from a file, cleans them, and checks their reputation."""
    results = []
    try:
        with open(filename, "r") as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                if url:  # Make sure it's not an empty line
                    clean_url_str = clean_url(url)
                    reputation_results = check_url_reputation(clean_url_str, vt_api_key)
                    results.append({"url": clean_url_str, "reputation": reputation_results})
        return results
    except FileNotFoundError:
        return {"error": f"File '{filename}' not found."}
    except Exception as e:
        return {"error": str(e)}
