import click
from pathlib import Path
from wave_cli import __version__
from wave_cli.report_generator import WavePDFReport
from wave_cli.report_parser import collect_findings
from wave_cli.scanners.gobuster_scanner import run_gobuster_dir
from wave_cli.scanners.subdomain_scanner import run_subdomain_enum
from wave_cli.utils import get_run_dir, get_output_file, cleanse_url
from wave_cli.scanners.internal_links_scraper import scrape_internal_links
from wave_cli.scanners.owasp.A04_cryptographic_failures import run_crypto_scan
from wave_cli.scanners.owasp.A02_security_headers import check_security_headers


def banner():
    click.echo(r"""
             __      ____ ___   ______ 
      .-``'. \ \ /\ / / _` \ \ / / _  \  .'''-.
    .`   .`~  \ V  V / (_| |\ V /  ___/  ~`.   '.
_.-'     '._   \_/\_/ \__,_| \_/ \____|  _.'     '-._
~--.__ Website Assessment Vulnerability Engine __.--~
               """)


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, message="WAVE v"+str(__version__))
@click.pass_context
def cli(ctx):
    """🌊🔍 WAVE - Website Assessment Vulnerability Engine"""
    if ctx.invoked_subcommand is None:
        banner()


@cli.command()
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Output PDF path")
@click.option("--gobuster-wordlist", "-g", type=click.Path(), default="dir-big.txt", help="Path to gobuster wordlist")
@click.option("--subdomain-wordlist", "-s", type=click.Path(), default="subdomains-top1million-20000.txt", help="Path to subdomain wordlist")
@click.option("--link-limit", "-l", type=int, default=100, help="Maximum number of links to scrape")
def scan(target, output, gobuster_wordlist, subdomain_wordlist, link_limit):
    """Scan a target website for vulnerabilities"""
    banner()

    run_dir = get_run_dir()
    cleaned_target = cleanse_url(target)
    click.echo(f"[*] Run directory : {run_dir}")
    click.echo(click.style(f"[*] Starting scan on {target}...\n", bold=True))


    """Step 1 : Running gobuster dir mode"""
    click.echo(f"[*] Step 1 : Running gobuster dir mode on {target}...")
    try:
        output_file_gobuster_dir = get_output_file("gobuster-dir", target, run_dir)
        run_gobuster_dir(target, output_file_gobuster_dir, wordlist=gobuster_wordlist)
        click.echo(click.style("[✓]", fg="green", bold=True) + f" Gobuster dir scan completed, output saved to {output_file_gobuster_dir}\n")
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Gobuster dir scan failed : {e}\n")
    

    """Step 2 : Scraping internal links"""
    click.echo(f"[*] Step 2 : Scraping internal links from {target}...")
    try:
        output_file_internal_links = get_output_file("internal-links", target, run_dir)
        scrape_internal_links(target, output_file_internal_links, scrap_limit=link_limit)
        click.echo(click.style("[✓]", fg="green", bold=True) + f" Internal links scraped, output saved to {output_file_internal_links}\n")
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Failed to scrape internal links : {e}\n")


    """Step 3 : Running gobuster dns mode"""
    click.echo(f"[*] Step 3 : Running gobuster dns mode on {cleaned_target}...")
    try:
        output_file_gobuster_dns = get_output_file("gobuster-dns", cleaned_target, run_dir)
        run_subdomain_enum(cleaned_target, output_file_gobuster_dns, wordlist=subdomain_wordlist)
        click.echo(click.style("[✓]", fg="green", bold=True) + f" Gobuster dns scan completed, output saved to {output_file_gobuster_dns}\n")
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Gobuster dns scan failed : {e}\n")


    """Step 4 : Checking security headers (OWASP A02)"""
    click.echo(f"[*] Step 4 : (OWASP A02:2025) Checking security headers on {target}...")
    try:
        output_file_headers = get_output_file("A02_security-headers", target, run_dir)
        check_security_headers(target, output_file_headers)
        click.echo(click.style("[✓]", fg="green", bold=True) + f" Security headers check completed, output saved to {output_file_headers}\n")
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Security headers check failed : {e}\n")


    """Step 5 : Checking cryptographic failures (OWASP A04)"""
    click.echo(f"[*] Step 5 : (OWASP A04:2025) Checking cryptographic failures on {target}...")
    try:
        output_file_crypto = get_output_file("A04_crypto-failures", target, run_dir)
        run_crypto_scan(target, output_file_crypto)
        click.echo(click.style("[✓]", fg="green", bold=True) + f" Cryptographic failures check completed, output saved to {output_file_crypto}\n")
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Cryptographic failures check failed : {e}\n")


    """Step X : Generating PDF report"""
    click.echo(f"[*] Step X : Generating PDF report...")
    try:
        findings = collect_findings(run_dir)
        
        # Déterminer le chemin du PDF
        if output:
            report_path = Path(output)
        else:
            report_path = run_dir / f"wave_report_{cleaned_target}.pdf"
        
        pdf_report = WavePDFReport(report_path, target)
        pdf_report.generate_report(findings)
        
        click.echo(click.style("[✓]", fg="green", bold=True) + f" PDF report generated : {report_path}")
    except Exception as e:
        click.echo(click.style("[!]", fg="red", bold=True) + f" Failed to generate report : {e}")


    click.echo(click.style("🎉 Scan completed !", bold=True))
    return 0

if __name__ == "__main__":
    cli()