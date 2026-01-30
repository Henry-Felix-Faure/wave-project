import re
import click
import requests
from pathlib import Path
from urllib.parse import urljoin, urlparse

# Supprimer le warning SSL de urllib3
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

def scrape_internal_links(initial_target: str,
                          output_file: Path,
                          scrap_limit: int = 100) -> str:
    """Scrape tous les liens <a href> d'une page."""

    targets = [initial_target]
    absolute_links = set()

    while len(targets) > 0 and len(absolute_links) < scrap_limit:
        current_target = targets.pop(0)
        try:
            response = requests.get(current_target, timeout=10, verify=False)
            response.raise_for_status()
        except Exception as e:
            click.echo(click.style("[✖]", fg="red", bold=True) + f" Failed to fetch {current_target}: {e}")
            continue
    
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
    
    return str(output_file)
