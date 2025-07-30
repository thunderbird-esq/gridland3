import argparse
from .analyze_cli import configure_analyze_parser, handle_analyze_command
from .discover_cli import configure_discover_parser, handle_discover_command

def main():
    """Main entry point for the GRIDLAND CLI."""
    parser = argparse.ArgumentParser(
        description="GRIDLAND: A comprehensive network device analysis toolkit."
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands"
    )

    # Configure the 'analyze' subcommand
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run the analysis engine against specified targets."
    )
    configure_analyze_parser(analyze_parser)

    # Configure the 'discover' subcommand
    discover_parser = subparsers.add_parser(
        "discover",
        help="Discover potential targets using various methods."
    )
    configure_discover_parser(discover_parser)

    args = parser.parse_args()

    # Dispatch to the appropriate handler based on the command
    if args.command == "analyze":
        handle_analyze_command(args)
    elif args.command == "discover":
        handle_discover_command(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
