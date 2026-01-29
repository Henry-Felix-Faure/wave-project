
import re
import datetime
from importlib import resources
from pathlib import Path
from urllib.parse import urlparse

def get_run_dir() -> Path:
    """Crée un dossier unique pour ce run."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')
    run_dir = Path("/tmp/wave_scans") / f"scan_{timestamp}"
    run_dir.mkdir(exist_ok=True, parents=True)
    return run_dir

def get_output_file(prefix: str, target: str, run_dir: Path, extension: str = "txt") -> Path:
    """Génère un fichier dans le dossier du run."""
    safe_target = target.replace('://', '_').replace('/', '_')
    return run_dir / f"{prefix}_{safe_target}.{extension}"

def get_wordlist(name: str) -> Path:
    """Récupère une wordlist depuis le package."""
    return resources.files("wave_cli.wordlists") / name

def extract_domain(target: str) -> str:
    """Extrait le domaine pur pour gobuster DNS."""
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # Nettoyage basique
    domain = re.sub(r'^www\.', '', domain.lower())
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r':\d+$', '', domain)  # Supprime le port
    domain = re.sub(r'/$', '', domain)
    
    # Regex permissive pour Gobuster DNS
    if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9](\.[a-z0-9][a-z0-9.-]*[a-z0-9])?$', domain):
        # Fallback: accepte aussi les IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return domain
        raise ValueError(f"Invalid domain: {domain}")
    
    return str(domain)
