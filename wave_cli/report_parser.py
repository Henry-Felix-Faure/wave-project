from pathlib import Path
from typing import Dict, List
import click

def parse_gobuster_output(file_path: Path) -> List[str]:
    """Parse la sortie gobuster et retourne les chemins trouvés."""
    findings = []
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('['):
                    # Format: /admin (Status: 200) [Size: 1234]
                    # On extrait juste la partie path
                    if '(Status:' in line:
                        path = line.split(' (Status:')[0].strip()
                        findings.append(path)
                    else:
                        findings.append(line)
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing gobuster output : {e}")
    
    return findings


def parse_subdomain_output(file_path: Path) -> List[str]:
    """Parse la sortie DNS gobuster et retourne les subdomains."""
    findings = []
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('['):
                    # Format similaire à gobuster dir
                    if 'Found:' in line:
                        subdomain = line.split('Found:')[1].strip()
                        findings.append(subdomain)
                    else:
                        findings.append(line)
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing subdomain output : {e}")
    
    return findings


def parse_internal_links_output(file_path: Path) -> List[str]:
    """Parse la sortie des liens internes."""
    findings = []
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, 'r') as f:
            findings = [line.strip() for line in f if line.strip()]
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Error parsing internal links : {e}")
    
    return findings


def collect_findings(run_dir: Path) -> Dict[str, List[str]]:
    """Collecte les résultats des différents scans dans un dictionnaire."""
    findings = {
        'Directories': [],
        'Subdomains': [],
        'Internal Links': []
    }
    
    # Chercher les fichiers de résultats
    for file_path in run_dir.glob('*.txt'):
        if 'gobuster-dir' in file_path.name:
            findings['Directories'] = parse_gobuster_output(file_path)
        elif 'gobuster-dns' in file_path.name:
            findings['Subdomains'] = parse_subdomain_output(file_path)
        elif 'internal_links' in file_path.name:
            findings['Internal Links'] = parse_internal_links_output(file_path)
    
    return findings
