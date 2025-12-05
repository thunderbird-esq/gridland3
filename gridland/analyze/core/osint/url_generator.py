"""OSINT URL Generator for GRIDLAND.

This module provides URL generation for various OSINT platforms including
Shodan, Censys, ZoomEye, and Google Dorking queries. URLs are formatted
exactly as specified in CamXploit.py for compatibility.
"""

from typing import Dict, List
from urllib.parse import quote_plus


class OSINTURLGenerator:
    """Generate OSINT platform search URLs for camera reconnaissance.

    This class provides methods to generate properly formatted URLs for
    various OSINT platforms and Google Dork queries. All URL formats match
    those used in CamXploit.py for consistency.

    Example:
        >>> generator = OSINTURLGenerator()
        >>> urls = generator.generate_search_urls("192.168.1.100")
        >>> print(urls['shodan'])
        https://www.shodan.io/search?query=192.168.1.100
    """

    @staticmethod
    def generate_search_urls(ip: str) -> dict[str, str]:
        """Generate OSINT platform search URLs for an IP address.

        Creates URLs for Shodan, Censys, ZoomEye, and a quick Google Dork
        search. All formats match CamXploit.py lines 853-858.

        Args:
            ip: IP address to search for (can be IPv4 or IPv6).

        Returns:
            Dict[str, str]: Dictionary with keys 'shodan', 'censys',
                            'zoomeye', 'google_quick' mapping to URLs.

        Example:
            >>> generator = OSINTURLGenerator()
            >>> urls = generator.generate_search_urls("203.0.113.1")
            >>> print(urls['shodan'])
            https://www.shodan.io/search?query=203.0.113.1
            >>> print(urls['censys'])
            https://search.censys.io/hosts/203.0.113.1
        """
        google_query = f"site:{ip}+inurl:view/view.shtml+OR+" f"inurl:admin.html+OR+inurl:login"
        return {
            "shodan": f"https://www.shodan.io/search?query={ip}",
            "censys": f"https://search.censys.io/hosts/{ip}",
            "zoomeye": f"https://www.zoomeye.org/searchResult?q={ip}",
            "google_quick": f"https://www.google.com/search?q={google_query}",
        }

    @staticmethod
    def generate_google_dorks(ip: str) -> list[dict[str, str]]:
        """Generate Google Dork queries for camera discovery.

        Creates 4 Google Dork queries as specified in CamXploit.py lines
        863-869. Each query targets different camera web interfaces.

        Args:
            ip: IP address to create dorks for.

        Returns:
            List[Dict[str, str]]: List of dicts with 'query' and 'url' keys.
                                  Queries are the raw search strings, URLs
                                  are properly encoded Google search links.

        Example:
            >>> generator = OSINTURLGenerator()
            >>> dorks = generator.generate_google_dorks("192.168.1.1")
            >>> print(dorks[0]['query'])
            site:192.168.1.1 inurl:view/view.shtml
            >>> print(len(dorks))
            4
        """
        queries = [
            f"site:{ip} inurl:view/view.shtml",
            f"site:{ip} inurl:admin.html",
            f"site:{ip} inurl:login",
            f"intitle:'webcam' inurl:{ip}",
        ]

        return [
            {
                "query": query,
                "url": f"https://www.google.com/search?q={quote_plus(query)}",
            }
            for query in queries
        ]
