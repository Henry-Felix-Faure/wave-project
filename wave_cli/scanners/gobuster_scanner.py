import subprocess
from pathlib import Path
from wave_cli.utils import get_wordlist

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
        "-s", "200,301,302,401",
        "-b", "",
        "--xl", "0",     # ne prend pas en compte les réponse de taille 0
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