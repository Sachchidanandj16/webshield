import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List

def audit_ssl_certificate(target_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname or target_url
    
    # Configure generic safe SSL Context
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Fetch Cipher and Protocol Information
                cipher_info = ssock.cipher()
                protocol_version = ssock.version()
                
                # Expiration parsing
                not_after_str = cert.get('notAfter')
                date_fmt = r"%b %d %H:%M:%S %Y %Z"
                
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, date_fmt).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days
                    
                    if days_remaining < 0:
                        findings.append({
                            "category": "SSL/TLS",
                            "item_checked": "Certificate Expiration",
                            "status": "Expired",
                            "severity": "High",
                            "description": "The TLS certificate for this host is expired.",
                            "recommendation": "Renew the TLS certificate immediately."
                        })
                    elif days_remaining < 30:
                        findings.append({
                            "category": "SSL/TLS",
                            "item_checked": "Certificate Expiration",
                            "status": "Expiring Soon",
                            "severity": "Medium",
                            "description": f"The TLS certificate is expiring soon ({days_remaining} days remaining).",
                            "recommendation": "Renew the certificate prior to expiration."
                        })
                    else:
                        findings.append({
                            "category": "SSL/TLS",
                            "item_checked": "Certificate Expiration",
                            "status": "Compliant",
                            "severity": "Info",
                            "description": f"Certificate is valid. Remaining days: {days_remaining}",
                            "recommendation": "No action required."
                        })
                
                # Cipher and protocol strength validation
                if protocol_version in ["TLSv1", "TLSv1.1"]:
                    findings.append({
                        "category": "SSL/TLS",
                        "item_checked": "Protocol Version",
                        "status": "Weak Protocol",
                        "severity": "High",
                        "description": f"Server configured with legacy TLS version: {protocol_version}.",
                        "recommendation": "Deprecate TLS 1.0/1.1 and enforce a minimum of TLS 1.2."
                    })
                else:
                    findings.append({
                        "category": "SSL/TLS",
                        "item_checked": "Protocol Version",
                        "status": "Compliant",
                        "severity": "Info",
                        "description": f"Server uses strong negotiation protocol: {protocol_version}",
                        "recommendation": "Maintain state."
                    })
                    
    except Exception as e:
        findings.append({
            "category": "SSL/TLS",
            "item_checked": "Handshake Negotiation",
            "status": "Handshake Failure",
            "severity": "Medium",
            "description": f"Failed negotiating safe connection: {str(e)}",
            "recommendation": "Audit TLS implementation or verify host supports TLS connections on standard port 443."
        })
        
    return findings