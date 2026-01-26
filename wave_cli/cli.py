# wave_cli/cli.py
import click
from wave_cli import __version__


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
def scan(target, output):
    """Scan a target website for vulnerabilities"""
    banner()
    click.echo(f"[*] Scanning {target}...")


if __name__ == "__main__":
    cli()