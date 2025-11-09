"""
Mock Shodan module for testing when shodan is not installable.
"""


class APIError(Exception):
    """Mock Shodan API error."""
    pass


class Shodan:
    """Mock Shodan API client."""

    def __init__(self, api_key):
        self.api_key = api_key

    def search(self, query, limit=100):
        """Mock search method."""
        return {'matches': []}
