import click

from .analyze_cli import analyze
from .discover_cli import discover

@click.group()
def main():
    """GRIDLAND: A comprehensive network device analysis toolkit."""
    pass

main.add_command(analyze)
main.add_command(discover)

if __name__ == '__main__':
    main()
