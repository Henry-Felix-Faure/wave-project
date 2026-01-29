
import re
import datetime
from pathlib import Path
from importlib import resources
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


def get_wordlist(name: str) -> str:
    """Récupère une wordlist (bundlée ou custom path)."""
    # 1. C'est un chemin absolu/relatif
    path = Path(name)
    if path.exists():
        return str(path.resolve())

    # 2. Sinon on cherche dans le package
    try:
        packaged_wordlist = resources.files("wave_cli.wordlists") / name
        return str(packaged_wordlist)
    except (FileNotFoundError, KeyError):
        raise FileNotFoundError(f"Wordlist not found : {name}")


def cleanse_url(target: str) -> str:
    """Nettoie l'URL"""
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
