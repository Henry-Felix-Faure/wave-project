# wave_cli/scanners/gobuster_scanner.py
import subprocess
from pathlib import Path
from wave_cli.scanners.utils import get_wordlist

def run_gobuster_dir(target: str,
                     output_file: Path,
                     wordlist: str = "dir-big.txt",
                     threads: int = 50,
                     ) -> str:
    """
    Lance gobuster dir sur une cible et renvoie la liste des chemins trouvés.
    """

    wordlist_path = get_wordlist(wordlist)
    
    cmd_gb = [
        "gobuster",
        "dir",
        "-u", target,
        "-w", wordlist_path,
        "-t", str(threads),
        "-o", str(output_file),
        "-s", "200,401,403",
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