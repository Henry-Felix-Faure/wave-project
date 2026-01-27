# wave_cli/scanners/gobuster_scanner.py
import subprocess
import datetime
from pathlib import Path

def run_gobuster_dir(target: str,
                     wordlist: str = "/usr/share/wordlists/dirb/big.txt",
                     threads: int = 50) -> Path:
    """
    Lance gobuster dir sur une cible et renvoie la liste des chemins trouvés.
    """
    
    # Fichier output avec timestamp
    output_file = Path("/tmp/wave_scans") / f"wave_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_gobuster_{target.replace('://', '_').replace('/', '_')}.txt"

    cmd_gb = [
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
        cmd_gb,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
        

    # found_paths: list[str] = []
    # if output_file.exists():
    #     with output_file.open() as f:
    #         for line in f:
    #             # Format typique: /admin (Status: 301) [Size: 0]
    #             found_paths.append(line.strip())

    return str(output_file)