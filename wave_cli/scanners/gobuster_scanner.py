# wave_cli/scanners/gobuster_scanner.py
import subprocess
from pathlib import Path

def run_gobuster_dir(target: str,
                     wordlist: str = "/usr/share/wordlists/dirb/big.txt",
                     threads: int = 50) -> list[str]:
    """
    Lance gobuster dir sur une cible et renvoie la liste des chemins trouvés.
    """
    output_file = Path("/tmp") / f"wave_gobuster_{target.replace('://', '_').replace('/', '_')}.txt"

    cmd = [
        "gobuster",
        "dir",
        "-u", target,
        "-w", wordlist,
        "-t", str(threads),
        "-o", str(output_file),
        "-s", "200,301,302,307,401,403",
        "-b", "",
        "-q",          # quiet (moins de bruit)
    ]

    result = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Gobuster failed: {result.stderr.strip()}")

    found_paths: list[str] = []
    if output_file.exists():
        with output_file.open() as f:
            for line in f:
                # Format typique: /admin (Status: 301) [Size: 0]
                found_paths.append(line.strip())

    return found_paths