import requests
from typing import Dict, Any, List

HEADER_POLICIES = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Restricts resources (such as JavaScript, CSS, Images) that the browser is allowed to load for a given page.",
        "recommendation": "Configure a strict Content-Security-Policy (CSP) with 'default-src' restrictions to mitigate XSS and data injection."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Declares that browsers should only interact with the server using secure HTTPS connections.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to response headers."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Controls whether a browser is allowed to render a page in a <frame>, <iframe>, <embed> or <object> tag.",
        "recommendation": "Deploy X-Frame-Options with 'DENY' or 'SAMEORIGIN' values to mitigate Clickjacking."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Opt-out of MIME type sniffing, forcing the browser to respect the Content-Type declared by the server.",
        "recommendation": "Configure response header 'X-Content-Type-Options: nosniff'."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Governs which referrer information, sent in the Referer header, should be included with requests made.",
        "recommendation": "Configure policy such as 'Referrer-Policy: strict-origin-when-cross-origin'."
    }
}

def audit_http_headers(url: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        # Perform safe HTTP HEAD or GET request to extract headers
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        return [{
            "category": "HTTP Header",
            "item_checked": "Connection Check",
            "status": "Failed Connection",
            "severity": "High",
            "description": f"Could not establish connection to analyze headers: {str(e)}",
            "recommendation": "Verify target DNS configuration and network availability."
        }]

    for header_name, policy in HEADER_POLICIES.items():
        header_val = headers.get(header_name)
        if not header_val:
            findings.append({
                "category": "HTTP Header",
                "item_checked": header_name,
                "status": "Missing",
                "severity": policy["severity"],
                "description": policy["description"],
                "recommendation": policy["recommendation"]
            })
        else:
            findings.append({
                "category": "HTTP Header",
                "item_checked": header_name,
                "status": "Compliant",
                "severity": "Info",
                "description": f"Header configured correctly with value: {header_val}",
                "recommendation": "No actions required."
            })
            
    return findings