import click

from src.gridland.cli.analyze_cli import analyze
from src.gridland.cli.discover_cli import discover

@click.group()
def main():
    """GRIDLAND: A comprehensive network device analysis toolkit."""
    pass

main.add_command(analyze)
main.add_command(discover)

if __name__ == '__main__':
    main()
