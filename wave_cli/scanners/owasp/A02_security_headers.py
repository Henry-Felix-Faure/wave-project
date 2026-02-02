import click
import requests
from pathlib import Path
from typing import Dict, List


# Headers critiques à vérifier (OWASP A02)
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Protects against XSS and code injection",
        "severity": "HIGH",
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS and protects against MITM",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing attacks",
        "severity": "MEDIUM",
    },
    "Referrer-Policy": {
        "description": "Controls information in Referrer header",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "description": "Controls access to features (camera, mic, etc.)",
        "severity": "LOW",
    }
}


def check_security_headers(target: str, output_file: Path) -> Dict[str, List]:
    """ Vérifie la présence des security headers critiques """
    results = {
        "missing": [],
        "present": [],
        "weak": []
    }
    
    try:
        # Requête GET pour récupérer les headers
        response = requests.get(
            target, 
            timeout=10, 
            verify=False,  # Ignore SSL pour pentest
            allow_redirects=True
        )
        
        click.echo(f"    [→] Checking {len(SECURITY_HEADERS)} security headers...")
        
        # Vérifier chaque header
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name in response.headers:
                header_value = response.headers[header_name]
                
                # Vérifier si configuration est faible
                weakness = check_header_weakness(header_name, header_value)
                if weakness:
                    results["weak"].append({
                        "header": header_name,
                        "value": header_value,
                        "issue": weakness,
                        "severity": header_info["severity"],
                        "description": header_info["description"]
                    })
                else:
                    results["present"].append({
                        "header": header_name,
                        "value": header_value[:80] + "..." if len(header_value) > 80 else header_value,
                        "description": header_info["description"]
                    })
            else:
                results["missing"].append({
                    "header": header_name,
                    "severity": header_info["severity"],
                    "description": header_info["description"],
                })
        
        # Sauvegarder les résultats
        save_results(output_file, results, target)
        
        # Afficher résumé
        missing_count = len(results["missing"])
        weak_count = len(results["weak"])
        present_count = len(results["present"])
        
        if missing_count > 0:
            click.echo(click.style(f"    [!] {missing_count} header(s) missing", fg="red"))
        if weak_count > 0:
            click.echo(click.style(f"    [!] {weak_count} header(s) with weak config", fg="yellow"))
        if present_count > 0:
            click.echo(click.style(f"    [✓] {present_count} header(s) properly configured", fg="green"))
        
    except requests.exceptions.RequestException as e:
        click.echo(click.style(f"    [✖] Failed to check headers: {e}", fg="red"))
        results["error"] = str(e)
    
    return results


def check_header_weakness(header_name: str, header_value: str) -> str:
    """ Vérifie si un header présent a une configuration faible """
    value_lower = header_value.lower()
    
    if header_name == "Strict-Transport-Security":
        # HSTS doit avoir max-age >= 31536000 (1 an)
        if "max-age" not in value_lower:
            return "Missing max-age directive"
        
        # Extraire max-age value
        try:
            max_age = int(value_lower.split("max-age=")[1].split(";")[0])
            if max_age < 31536000:
                return f"max-age too short ({max_age}s < 1 year)"
        except:
            return "Invalid max-age format"
    
    elif header_name == "X-Frame-Options":
        # Doit être DENY ou SAMEORIGIN
        if value_lower not in ["deny", "sameorigin"]:
            return f"Weak value: {header_value}"
    
    elif header_name == "X-Content-Type-Options":
        # Doit être nosniff
        if value_lower != "nosniff":
            return f"Expected 'nosniff', got '{header_value}'"
    
    elif header_name == "Content-Security-Policy":
        # CSP trop permissive
        if "'unsafe-inline'" in value_lower or "'unsafe-eval'" in value_lower:
            return "Contains 'unsafe-inline' or 'unsafe-eval' (dangerous)"
    
    return None


def save_results(output_file: Path, results: Dict, target: str):
    """Sauvegarde les résultats dans un fichier."""
    with output_file.open("w") as f:
        f.write(f"Security Headers Analysis for {target}\n")
        f.write("=" * 60 + "\n\n")
        
        # Headers manquants
        if results["missing"]:
            f.write(f"MISSING HEADERS ({len(results['missing'])}):\n")
            f.write("-" * 60 + "\n")
            for item in results["missing"]:
                f.write(f"• {item['header']} [{item['severity']}]\n")
                f.write(f"  → {item['description']}\n")
                f.write(f"  → OWASP: A02:2025 - Security Misconfiguration\n\n")
        
        # Headers faibles
        if results["weak"]:
            f.write(f"\nWEAK CONFIGURATIONS ({len(results['weak'])}):\n")
            f.write("-" * 60 + "\n")
            for item in results["weak"]:
                f.write(f"• {item['header']} [{item['severity']}]\n")
                f.write(f"  Current: {item['value']}\n")
                f.write(f"  Issue: {item['issue']}\n\n")
        
        # Headers présents (OK)
        if results["present"]:
            f.write(f"\nPROPERLY CONFIGURED ({len(results['present'])}):\n")
            f.write("-" * 60 + "\n")
            for item in results["present"]:
                f.write(f"✓ {item['header']}\n")
                f.write(f"  {item['value']}\n\n")
                
    return