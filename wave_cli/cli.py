# wave_cli/cli.py
import click
from pathlib import Path
from wave_cli import __version__
from wave_cli.scanners.gobuster_scanner import run_gobuster_dir
from wave_cli.scanners.internal_links_scraper import scrape_internal_links


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, message="WAVE v"+str(__version__))
@click.pass_context
def cli(ctx):
    """🌊🔍 WAVE - Website Assessment Vulnerability Engine"""
    if ctx.invoked_subcommand is None:
        banner()


def banner():
    click.echo(r"""
             __      ____ ___   ______ 
      .-``'. \ \ /\ / / _` \ \ / / _  \  .'''-.
    .`   .`~  \ V  V / (_| |\ V /  ___/  ~`.   '.
_.-'     '._   \_/\_/ \__,_| \_/ \____|  _.'     '-._
~--.__ Website Assessment Vulnerability Engine __.--~
               """)


@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output PDF path")
@click.option("--gobuster-wordlist", "-w", type=click.Path(), default="/usr/share/wordlists/dirb/big.txt", help="Path to gobuster wordlist")
@click.option("--link-limit", "-ll", type=int, default=100, help="Maximum number of links to scrape")
def scan(target, output, gobuster_wordlist, link_limit):
    """Scan a target website for vulnerabilities"""
    banner()

    # Créer le dossier /tmp/wave_scans s'il n'existe pas
    scan_dir = Path("/tmp/wave_scans")
    scan_dir.mkdir(exist_ok=True)  # Pas d'erreur si existe

    click.echo(f"[*] Starting scan on {target}...")

    """Step 1 : Running gobuster"""
    click.echo(f"[*] Step 1 : Running gobuster on {target}...")
    try:
        output_file_gobuster = run_gobuster_dir(target, wordlist=gobuster_wordlist)
        click.echo(f"[✓] Gobuster scan completed, output saved to {output_file_gobuster}")
    except Exception as e:
        click.echo(f"[!] Gobuster failed : {e}")
    
    """Step 2 : Scraping internal links"""
    click.echo(f"[*] Step 2 : Scraping internal links from {target}...")
    try:
        output_file_internal_links = scrape_internal_links(target, scrap_limit=link_limit)
        click.echo(f"[✓] Internal links scraped, output saved to {output_file_internal_links}")
    except Exception as e:
        click.echo(f"[!] Failed to scrape internal links: {e}")

    
    click.echo("[✓] Scan completed successfully!")
    return 0

if __name__ == "__main__":
    cli()