
import datetime
from importlib import resources
from pathlib import Path

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
