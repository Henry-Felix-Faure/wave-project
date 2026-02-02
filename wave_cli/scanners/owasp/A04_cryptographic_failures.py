import ssl
import click
import socket
import requests
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from urllib.parse import urlparse


def check_https_redirect(target: str) -> Dict[str, Any]:
    """ Vérifie si le site HTTP redirige vers HTTPS """
    result = {
        "check": "HTTPS Redirect",
        "has_https": False,
        "redirects_to_https": False,
        "final_url": "",
        "status": "failed",
        "message": ""
    }
    
    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        
        # Test HTTP → HTTPS redirect
        http_url = f"http://{domain}"
        https_url = f"https://{domain}"
        
        # Vérifie si HTTPS est disponible
        try:
            https_resp = requests.get(https_url, timeout=5, allow_redirects=True)
            result["has_https"] = https_resp.status_code == 200
        except requests.RequestException:
            result["has_https"] = False
        
        # Vérifie la redirection HTTP → HTTPS
        http_resp = requests.get(http_url, timeout=5, allow_redirects=True)
        result["final_url"] = http_resp.url
        
        if http_resp.url.startswith("https://"):
            result["redirects_to_https"] = True
            result["status"] = "passed"
            result["message"] = "HTTP redirects to HTTPS"
        elif result["has_https"]:
            result["status"] = "warning"
            result["message"] = "HTTPS available but no redirect from HTTP"
        else:
            result["status"] = "failed"
            result["message"] = "No HTTPS available"
    
    except requests.RequestException as e:
        result["status"] = "error"
        result["message"] = f"Connection error: {str(e)}"
    
    return result


def check_ssl_certificate(target: str) -> Dict[str, Any]:
    """ Valide le certificat SSL (expiration, CN, issuer) """
    result = {
        "check": "SSL Certificate",
        "valid": False,
        "expires_in_days": None,
        "expiry_date": "",
        "issuer": "",
        "subject": "",
        "status": "failed",
        "message": ""
    }
    
    try:
        parsed = urlparse(target)
        hostname = parsed.netloc or parsed.path
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extraire les infos du certificat
                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expiry_date - datetime.now()).days
                result["expiry_date"] = expiry_date.strftime("%Y-%m-%d")
                result["expires_in_days"] = days_remaining
                
                # Extraire issuer et subject
                if "issuer" in cert:
                    issuer_parts = dict(x[0] for x in cert["issuer"])
                    result["issuer"] = issuer_parts.get("organizationName", "Unknown")
                
                if "subject" in cert:
                    subject_parts = dict(x[0] for x in cert["subject"])
                    result["subject"] = subject_parts.get("commonName", "Unknown")
                
                # Évaluation
                if days_remaining < 0:
                    result["status"] = "failed"
                    result["message"] = f"Certificate EXPIRED {abs(days_remaining)} days ago"
                elif days_remaining < 30:
                    result["status"] = "warning"
                    result["message"] = f"Certificate expires soon ({days_remaining} days)"
                else:
                    result["valid"] = True
                    result["status"] = "passed"
                    result["message"] = f"Valid certificate ({days_remaining} days remaining)"
    
    except ssl.SSLCertVerificationError as e:
        result["status"] = "failed"
        result["message"] = f"Certificate verification failed: {str(e)}"
    except (socket.error, ssl.SSLError) as e:
        result["status"] = "error"
        result["message"] = f"SSL connection error: {str(e)}"
    
    return result


def check_tls_version(target: str) -> Dict[str, Any]:
    """ Détecte la version TLS utilisée (TLS 1.0/1.1 sont obsolètes) """
    result = {
        "check": "TLS Version",
        "tls_version": "",
        "is_secure": False,
        "status": "failed",
        "message": ""
    }
    
    try:
        parsed = urlparse(target)
        hostname = parsed.netloc or parsed.path
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                result["tls_version"] = tls_version
                
                # TLS 1.2+ = sécurisé, TLS 1.0/1.1 = obsolète
                if tls_version in ["TLSv1.2", "TLSv1.3"]:
                    result["is_secure"] = True
                    result["status"] = "passed"
                    result["message"] = f"Secure TLS version ({tls_version})"
                elif tls_version in ["TLSv1", "TLSv1.1"]:
                    result["status"] = "warning"
                    result["message"] = f"Obsolete TLS version ({tls_version}) - Upgrade to TLS 1.2+"
                elif tls_version.startswith("SSL"):
                    result["status"] = "warning"
                    result["message"] = f"CRITICAL: Insecure SSL version ({tls_version})"
                else:
                    result["status"] = "failed"
                    result["message"] = f"Unknown TLS version: {tls_version}"
    
    except (socket.error, ssl.SSLError) as e:
        result["status"] = "error"
        result["message"] = f"TLS connection error: {str(e)}"
    
    return result


def run_crypto_scan(target: str, output_file: str) -> Dict[str, Any]:
    """ Exécute tous les scans cryptographiques """
    results = {
        "target": target,
        "https": None,
        "ssl_cert": None,
        "tls_version": None
    }
    
    # 1. HTTPS Redirect Check
    click.echo(f"    [→] Checking HTTPS redirect...")
    results["https"] = check_https_redirect(target)
    
    # 2. SSL Certificate Check
    click.echo(f"    [→] Fetching SSL certificate...")
    results["ssl_cert"] = check_ssl_certificate(target)
    
    # 3. TLS Version Check
    click.echo(f"    [→] Checking TLS version...")
    results["tls_version"] = check_tls_version(target)

    save_results(output_file, results, target)

    return output_file


def save_results(output_file: Path, results: Dict[str, Any], target: str) -> None:
    """ Sauvegarde les résultats dans l'output_file """
    with output_file.open("w") as f:
        f.write(f"Cryptographic failures basic analysis for {target}\n")
        f.write("=" * 60 + "\n\n")

        https = results.get("https")
        if https:
            f.write("HTTPS Redirect check :\n")
            f.write("-" * 60 + "\n")
            f.write(f"• Result : {https.get('status', '').upper()}\n")
            f.write(f" → {https.get('message', '')}\n")
            f.write(f" → Final URL : {https.get('final_url', '')}\n")
            f.write(" → OWASP: A04:2025 - Cryptographic Failures\n\n")

        ssl_cert = results.get("ssl_cert")
        if ssl_cert:
            f.write("SSL Certificate check :\n")
            f.write("-" * 60 + "\n")
            f.write(f"• Result : {ssl_cert.get('status', '').upper()}\n")
            f.write(f" → {ssl_cert.get('message', '')}\n")
            f.write(f" → Expiry Date : {ssl_cert.get('expiry_date', '')}\n")
            f.write(f" → Issuer : {ssl_cert.get('issuer', '')}\n")
            f.write(f" → Subject : {ssl_cert.get('subject', '')}\n")
            f.write(" → OWASP: A04:2025 - Cryptographic Failures\n\n")

        tls_version = results.get("tls_version")
        if tls_version:
            f.write("TLS Version check :\n")
            f.write("-" * 60 + "\n")
            f.write(f"• Result : {tls_version.get('status', '').upper()}\n")
            f.write(f" → {tls_version.get('message', '')}\n")
            f.write(" → OWASP: A04:2025 - Cryptographic Failures\n\n")
            
    return