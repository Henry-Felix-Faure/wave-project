import ssl
import click
import socket
import requests
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from urllib.parse import urlparse


def check_https_redirect(target: str) -> Dict[str, Any]:
    """ Teste HTTPS redirect pour apex ET www subdomain """
    result = {
        'check': 'HTTPS Redirect',
        'apex_https': False,
        'www_https': False,
        'apex_redirects_https': False,
        'www_redirects_https': False,
        'apex_final_url': '',
        'www_final_url': '',
        'status': 'failed',
        'message': ''
    }

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
    }

    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path  # ex: google.com

        apex_host = domain
        www_host = f"www.{domain}" if not domain.startswith("www.") else domain

        apex_http = f'http://{apex_host}'
        www_http = f'http://{www_host}'

        # 1) HTTP → ?
        apex_resp = requests.get(apex_http, timeout=8, allow_redirects=True,
                                 headers=headers, verify=False)
        result['apex_final_url'] = apex_resp.url
        result['apex_redirects_https'] = apex_resp.url.startswith('https://')

        www_resp = requests.get(www_http, timeout=8, allow_redirects=True,
                                headers=headers, verify=False)
        result['www_final_url'] = www_resp.url
        result['www_redirects_https'] = www_resp.url.startswith('https://')

        # 2) HTTPS direct (apex)
        try:
            r_apex_https = requests.get(f'https://{apex_host}', timeout=8, headers=headers)
            result['apex_https'] = r_apex_https.ok
        except requests.RequestException:
            result['apex_https'] = False

        # 3) HTTPS direct (www)
        try:
            r_www_https = requests.get(f'https://{www_host}', timeout=8, headers=headers)
            result['www_https'] = r_www_https.ok
        except requests.RequestException:
            result['www_https'] = False

        # 4) Évaluation
        if result['apex_redirects_https'] or result['www_redirects_https']:
            result['status'] = 'passed'
            result['message'] = (
                f'HTTPS redirect detected '
                f'(apex_final={result["apex_final_url"]}, '
                f'www_final={result["www_final_url"]})'
            )
        elif result['apex_https'] or result['www_https']:
            result['status'] = 'warning'
            result['message'] = (
                'HTTPS available but HTTP does not clearly redirect '
                f'(apex_final={result["apex_final_url"]}, '
                f'www_final={result["www_final_url"]})'
            )
        else:
            result['status'] = 'failed'
            result['message'] = (
                'Neither HTTPS redirect nor HTTPS endpoint detected '
                f'(apex_final={result["apex_final_url"]}, '
                f'www_final={result["www_final_url"]})'
            )

    except requests.RequestException as e:
        result['status'] = 'error'
        result['message'] = f'Network error: {str(e)}'

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
    """ Sauvegarde les résultats avec apex + www """
    with output_file.open('w') as f:
        f.write(f"Cryptographic failures analysis for {target}\n")
        f.write("=" * 60 + "\n")
        
        https = results.get('https')
        if https:
            f.write("HTTPS Redirect check (Apex & www)\n")
            f.write("-" * 60 + "\n")
            
            # Apex
            f.write(f"Apex (http://{target.split('//')[1].split('/')[0]}): Result {str(https['apex_redirects_https']).upper()}\n")
            f.write(f"  Final URL: {https['apex_final_url']}\n")
            
            # www
            f.write(f"www (http://www.{target.split('//')[1].split('/')[0]}): Result {str(https['www_redirects_https']).upper()}\n")
            f.write(f"  Final URL: {https['www_final_url']}\n")
            
            f.write(f"Overall: {https['status'].upper()}: {https['message']}\n")
            f.write("OWASP A04:2025 - Cryptographic Failures\n")
        

        ssl_cert = results.get('ssl_cert')
        if ssl_cert:
            f.write("\nSSL Certificate check\n")
            f.write("-" * 60 + "\n")
            f.write(f"Result: {ssl_cert['status'].upper()}\n")
            f.write(f"{ssl_cert['message']}\n")
            f.write(f"Expiry Date: {ssl_cert.get('expiry_date', 'N/A')}\n")
            f.write(f"Issuer: {ssl_cert.get('issuer', 'N/A')}\n")
            f.write(f"Subject: {ssl_cert.get('subject', 'N/A')}\n")
            f.write("OWASP A04:2025 - Cryptographic Failures\n")


        tls_version = results.get('tls_version')
        if tls_version:
            f.write("\nTLS Version check\n")
            f.write("-" * 60 + "\n")
            f.write(f"Result: {tls_version['status'].upper()}\n")
            f.write(f"{tls_version['message']}\n")
            f.write("OWASP A04:2025 - Cryptographic Failures\n")