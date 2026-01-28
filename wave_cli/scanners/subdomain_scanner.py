import subprocess
from pathlib import Path
import datetime
from urllib.parse import urlparse
from wave_cli.scanners.utils import get_wordlist

def extract_domain(target: str) -> str:
    """Extrait le domaine d'une URL."""
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    return domain.replace('www.', '')

def run_subdomain_enum(target: str,
                       output_file: Path,
                       wordlist: str = "subdomains-top1million-20000.txt",
                       threads: int = 50) -> str:
    """
    Énumère les sous-domaines avec gobuster DNS.
    """
    
    domain = extract_domain(target)
    wordlist_path = get_wordlist(wordlist)

    cmd = [
        "gobuster",
        "dns",
        "-d", domain,
        "-w", wordlist_path,
        "-t", str(threads),
        "-o", str(output_file),
        "-q"
    ]
    
    result = subprocess.run(
        cmd, 
        text=True, 
        capture_output=True
    )
    
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    
    return str(output_file)
