# wave_cli/cli.py
import click
from wave_cli import __version__
from wave_cli.scanners.gobuster_scanner import run_gobuster_dir


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, message="WAVE v"+str(__version__))
@click.pass_context
def cli(ctx):
    """🔍 WAVE - Website Assessment Vulnerability Engine"""
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
def scan(target, output, gobuster_wordlist):
    """Scan a target website for vulnerabilities"""
    banner()
    click.echo(f"[*] Starting scan on {target}...")
    click.echo(f"[*] Step 1 : Running gobuster on {target}...")
    try:
        output_file_gobuster = run_gobuster_dir(target, wordlist=gobuster_wordlist)
        click.echo(f"[✓] Gobuster scan completed, output saved to {output_file_gobuster}")
    except Exception as e:
        click.echo(f"[!] Gobuster failed : {e}")
        return

if __name__ == "__main__":
    cli()