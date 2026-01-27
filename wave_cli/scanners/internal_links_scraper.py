import re
import click
import datetime
import requests
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlparse

def scrape_internal_links(initial_target: str,
                          scrap_limit: int = 100) -> Path:
    """Scrape tous les liens <a href> d'une page."""

    # Fichier output avec timestamp
    output_file = Path("/tmp/wave_scans") / f"wave_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_internal_links_{initial_target.replace('://', '_').replace('/', '_')}.txt"
    
    cmd_gb = ["touch", str(output_file)]

    result = subprocess.run(
        cmd_gb,
        text=False,
        capture_output=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    
    targets = [initial_target]
    absolute_links = set()

    while len(targets) > 0 and len(absolute_links) < scrap_limit:
        current_target = targets.pop(0)
        try:
            response = requests.get(current_target, timeout=10)
            response.raise_for_status()
        except Exception as e:
            click.echo(f"[✖] Failed to fetch {current_target}: {e}")
            # raise RuntimeError(f"Failed to fetch {current_target}: {e}")
    
        # Extraire tous les href
        links = re.findall(r'href=["\'](.*?)["\']', response.text)
    
        # Normaliser les URLs (relatives → absolues)
        for link in links:
            try:
                absolute_url = urljoin(current_target, link)
                # Garder seulement les URLs du même domaine
                if urlparse(absolute_url).netloc == urlparse(current_target).netloc:
                    absolute_links.add(absolute_url)
                    if absolute_url not in targets and absolute_url not in absolute_links:
                        targets.append(absolute_url)
            except:
                pass
    
    # Sauvegarder les liens dans le fichier
    with output_file.open("w") as f:
        for link in absolute_links:
            f.write(link + "\n")
    
    return output_file
