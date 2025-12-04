"""Unit tests for OSINT URL Generator.

Tests URL generation for Shodan, Censys, ZoomEye, and Google Dork queries.
"""

from gridland.analyze.core.osint.url_generator import OSINTURLGenerator


class TestOSINTURLGenerator:
    """Tests for OSINTURLGenerator class."""

    def test_generate_search_urls_ipv4(self):
        """Test search URL generation for IPv4 address."""
        generator = OSINTURLGenerator()
        urls = generator.generate_search_urls("192.168.1.100")

        assert "shodan" in urls
        assert "censys" in urls
        assert "zoomeye" in urls
        assert "google_quick" in urls

        # Verify exact URL formats from CamXploit.py
        assert urls["shodan"] == "https://www.shodan.io/search?query=192.168.1.100"
        assert urls["censys"] == "https://search.censys.io/hosts/192.168.1.100"
        assert urls["zoomeye"] == "https://www.zoomeye.org/searchResult?q=192.168.1.100"
        assert "site:192.168.1.100" in urls["google_quick"]
        assert "inurl:view/view.shtml" in urls["google_quick"]

    def test_generate_search_urls_public_ip(self):
        """Test search URL generation for public IP."""
        generator = OSINTURLGenerator()
        urls = generator.generate_search_urls("8.8.8.8")

        assert urls["shodan"] == "https://www.shodan.io/search?query=8.8.8.8"
        assert urls["censys"] == "https://search.censys.io/hosts/8.8.8.8"
        assert urls["zoomeye"] == "https://www.zoomeye.org/searchResult?q=8.8.8.8"

    def test_generate_search_urls_ipv6(self):
        """Test search URL generation for IPv6 address."""
        generator = OSINTURLGenerator()
        ipv6 = "2001:4860:4860::8888"
        urls = generator.generate_search_urls(ipv6)

        assert ipv6 in urls["shodan"]
        assert ipv6 in urls["censys"]
        assert ipv6 in urls["zoomeye"]

    def test_generate_google_dorks_count(self):
        """Test that exactly 4 Google Dork queries are generated."""
        generator = OSINTURLGenerator()
        dorks = generator.generate_google_dorks("192.168.1.1")

        assert len(dorks) == 4
        assert all(isinstance(d, dict) for d in dorks)
        assert all("query" in d and "url" in d for d in dorks)

    def test_generate_google_dorks_queries(self):
        """Test Google Dork query content matches CamXploit.py."""
        generator = OSINTURLGenerator()
        ip = "10.0.0.1"
        dorks = generator.generate_google_dorks(ip)

        # Verify exact queries from CamXploit.py lines 863-867
        expected_queries = [
            f"site:{ip} inurl:view/view.shtml",
            f"site:{ip} inurl:admin.html",
            f"site:{ip} inurl:login",
            f"intitle:'webcam' inurl:{ip}",
        ]

        actual_queries = [d["query"] for d in dorks]
        assert actual_queries == expected_queries

    def test_generate_google_dorks_url_encoding(self):
        """Test that Google Dork URLs are properly encoded."""
        generator = OSINTURLGenerator()
        dorks = generator.generate_google_dorks("192.168.1.1")

        for dork in dorks:
            # URLs should be properly encoded
            assert "https://www.google.com/search?q=" in dork["url"]
            # Spaces should be encoded as +
            if " " in dork["query"]:
                assert "+" in dork["url"] or "%20" in dork["url"]

    def test_generate_google_dorks_view_shtml(self):
        """Test first Google Dork targets view/view.shtml."""
        generator = OSINTURLGenerator()
        dorks = generator.generate_google_dorks("172.16.0.1")

        assert "inurl:view/view.shtml" in dorks[0]["query"]
        assert "site:172.16.0.1" in dorks[0]["query"]

    def test_generate_google_dorks_admin_html(self):
        """Test second Google Dork targets admin.html."""
        generator = OSINTURLGenerator()
        dorks = generator.generate_google_dorks("172.16.0.1")

        assert "inurl:admin.html" in dorks[1]["query"]

    def test_generate_google_dorks_login(self):
        """Test third Google Dork targets login pages."""
        generator = OSINTURLGenerator()
        dorks = generator.generate_google_dorks("172.16.0.1")

        assert "inurl:login" in dorks[2]["query"]

    def test_generate_google_dorks_webcam_title(self):
        """Test fourth Google Dork uses intitle search."""
        generator = OSINTURLGenerator()
        dorks = generator.generate_google_dorks("172.16.0.1")

        assert "intitle:'webcam'" in dorks[3]["query"]
        assert "inurl:172.16.0.1" in dorks[3]["query"]

    def test_static_method_callable_without_instance(self):
        """Test that static methods work without instantiation."""
        urls = OSINTURLGenerator.generate_search_urls("1.1.1.1")
        assert len(urls) == 4

        dorks = OSINTURLGenerator.generate_google_dorks("1.1.1.1")
        assert len(dorks) == 4

    def test_url_consistency_across_calls(self):
        """Test that identical inputs produce identical outputs."""
        generator = OSINTURLGenerator()
        ip = "203.0.113.1"

        urls1 = generator.generate_search_urls(ip)
        urls2 = generator.generate_search_urls(ip)

        assert urls1 == urls2

        dorks1 = generator.generate_google_dorks(ip)
        dorks2 = generator.generate_google_dorks(ip)

        assert dorks1 == dorks2

    def test_special_characters_in_ip(self):
        """Test handling of edge case IP formats."""
        generator = OSINTURLGenerator()

        # IPv6 with brackets (shouldn't break)
        urls = generator.generate_search_urls("[2001:db8::1]")
        assert "[2001:db8::1]" in urls["shodan"]

    def test_all_urls_are_https(self):
        """Test that all generated URLs use HTTPS."""
        generator = OSINTURLGenerator()
        urls = generator.generate_search_urls("8.8.8.8")

        for url in urls.values():
            assert url.startswith("https://")

        dorks = generator.generate_google_dorks("8.8.8.8")
        for dork in dorks:
            assert dork["url"].startswith("https://")
