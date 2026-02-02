import click
from pathlib import Path
from typing import Dict, List

def parse_gobuster_output(file_path: Path) -> List[str]:
    """Parse la sortie gobuster et retourne les chemins trouvés """
    findings = []
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("["):
                    # Format: /admin (Status: 200) [Size: 1234]
                    # On extrait juste la partie path
                    if "(Status:" in line:
                        path = line.split(" (Status:")[0].strip()
                        findings.append(path)
                    else:
                        findings.append(line)
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing gobuster output : {e}")
    
    return findings


def parse_subdomain_output(file_path: Path) -> List[str]:
    """ Parse la sortie DNS gobuster et retourne les subdomains """
    findings = []
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("["):
                    # Format similaire à gobuster dir
                    if "Found:" in line:
                        subdomain = line.split("Found:")[1].strip()
                        findings.append(subdomain)
                    else:
                        findings.append(line)
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing subdomain output : {e}")
    
    return findings


def parse_internal_links_output(file_path: Path) -> List[str]:
    """ Parse la sortie des liens internes."""
    findings = []
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, "r") as f:
            findings = [line.strip() for line in f if line.strip()]
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing internal links : {e}")
    
    return findings


def parse_security_headers_output(file_path: Path) -> Dict[str, List[str]]:
    """ Parse la sortie du security headers checker """
    findings = {
        "missing_high": [],
        "missing_medium": [],
        "missing_low": [],
        "weak": []
    }
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, "r") as f:
            content = f.read()
            
            # Parser headers manquants par sévérité
            if "MISSING HEADERS" in content:
                section = content.split("MISSING HEADERS")[1].split("\n\n\n")[0]
                for line in section.split("\n"):
                    if "[HIGH]" in line:
                        header = line.split("• ")[1].split(" [")[0]
                        findings["missing_high"].append(header)
                    elif "[MEDIUM]" in line:
                        header = line.split("• ")[1].split(" [")[0]
                        findings["missing_medium"].append(header)
                    elif "[LOW]" in line:
                        header = line.split("• ")[1].split(" [")[0]
                        findings["missing_low"].append(header)
            
            # Parser configurations faibles
            if "WEAK CONFIGURATIONS" in content:
                section = content.split("WEAK CONFIGURATIONS")[1].split("\n\n\n")[0]
                for line in section.split("\n"):
                    if line.strip().startswith("•"):
                        findings["weak"].append(line.strip()[2:])
    
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing security headers: {e}")
    
    return findings

def parse_crypto_failures_output(file_path: Path) -> Dict[str, List[str]]:
    """ Parse la sortie du scan cryptographique A04 et retourne des messages prêts pour le rapport """
    findings: Dict[str, List[str]] = {
        "https": [],
        "ssl_cert": [],
        "tls_version": [],
    }

    if not file_path.exists():
        return findings

    try:
        with open(file_path, "r") as f:
            content = f.read()

        # On découpe en blocs par section
        sections = content.split("\n\n")

        current_section = None
        for block in sections:
            block = block.strip()
            if not block:
                continue
            # Détection de la section courante
            if block.startswith("HTTPS Redirect check"):
                current_section = "https"
                continue
            elif block.startswith("SSL Certificate check"):
                current_section = "ssl_cert"
                continue
            elif block.startswith("TLS Version check"):
                current_section = "tls_version"
                continue

            if current_section is None:
                continue

            # On récupère le status + message principal
            lines = [l.strip() for l in block.splitlines() if l.strip()]
            status = None
            message = None
            extra = []

            for line in lines:
                if line.startswith("• Result"):
                    # ex: "• Result : WARNING"
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        status = parts[1].strip()
                elif line.startswith("→"):
                    # ex: " → HTTPS available but no redirect from HTTP"
                    text = line.lstrip("→").strip()
                    # On ignore juste la ligne OWASP qui est redondante
                    if text.startswith("OWASP:"):
                        continue
                    if message is None:
                        message = text
                    else:
                        extra.append(text)

            if status and message:
                base = f"[{status}] {message}"
                # Ajouter les infos complémentaires (expiry, issuer, TLS version, etc.) sur la même ligne
                if extra:
                    base += " | " + " | ".join(extra)
                findings[current_section].append(base)

    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing crypto failures output: {e}")

    return findings


def collect_findings(run_dir: Path) -> Dict[str, List[str]]:
    """Collecte les résultats des différents scans dans un dictionnaire."""
    findings = {
        "Directories": [],
        "Subdomains": [],
        "Internal Links": [],
        "Security Issues": [],
        "Crypto Issues": [],
    }
    
    # Chercher les fichiers de résultats
    for file_path in run_dir.glob("*.txt"):
        if "gobuster-dir" in file_path.name:
            findings["Directories"] = parse_gobuster_output(file_path)

        elif "gobuster-dns" in file_path.name:
            findings["Subdomains"] = parse_subdomain_output(file_path)
            
        elif "internal-links" in file_path.name:
            findings["Internal Links"] = parse_internal_links_output(file_path)

        elif "A02_security-headers" in file_path.name:
            headers_findings = parse_security_headers_output(file_path)
            # Formater pour le rapport
            for header in headers_findings["missing_high"]:
                findings["Security Issues"].append(f"[HIGH] Missing header: {header}")
            for header in headers_findings["missing_medium"]:
                findings["Security Issues"].append(f"[MEDIUM] Missing header: {header}")
            for header in headers_findings["missing_low"]:
                findings["Security Issues"].append(f"[LOW] Missing header: {header}")            
            for weak in headers_findings["weak"]:
                findings["Security Issues"].append(f"[WEAK] {weak}")
        
        elif "A04_crypto-failures" in file_path.name:
            crypto_findings = parse_crypto_failures_output(file_path)
            for item in crypto_findings.get("https", []):
                findings["Crypto Issues"].append(f"[HTTPS] {item}")
            for item in crypto_findings.get("ssl_cert", []):
                findings["Crypto Issues"].append(f"[CERT] {item}")
            for item in crypto_findings.get("tls_version", []):
                findings["Crypto Issues"].append(f"[TLS] {item}")

    
    return findings
