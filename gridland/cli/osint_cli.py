"""
GRIDLAND OSINT CLI Module

Command-line interface for OSINT capabilities:
- Google dork query generation
- IP geolocation lookup
- Search engine URL generation

Usage:
    gridland osint dorks <IP>
    gridland osint geolocate <IP>
    gridland osint search-urls <IP>
    gridland osint full <IP>
"""

import json
import click

from gridland.core.osint import (
    get_osint_engine,
    get_search_urls,
    get_google_dork_urls,
    get_geolocation,
    osint_report,
)


@click.group(name="osint")
def osint_cli():
    """Open Source Intelligence (OSINT) commands for camera investigation."""
    pass


@osint_cli.command(name="dorks")
@click.argument("ip")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def dorks_command(ip: str, json_output: bool):
    """Generate Google dork queries for an IP address.
    
    Example: gridland osint dorks 192.168.1.1
    """
    engine = get_osint_engine()
    dorks = engine.get_google_dorks(ip)
    
    if json_output:
        output = [{"query": d.query, "url": d.search_url, "category": d.category} for d in dorks]
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(f"\n🔍 Google Dorks for {ip}")
        click.echo("=" * 60)
        
        # Group by category
        categories = {}
        for dork in dorks:
            if dork.category not in categories:
                categories[dork.category] = []
            categories[dork.category].append(dork)
        
        for category, category_dorks in categories.items():
            click.echo(f"\n📁 {category.upper()}")
            for dork in category_dorks:
                click.echo(f"  🔗 {dork.query}")
                click.echo(f"     {dork.search_url}")


@osint_cli.command(name="geolocate")
@click.argument("ip")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def geolocate_command(ip: str, json_output: bool):
    """Get IP geolocation information via ipinfo.io.
    
    Example: gridland osint geolocate 8.8.8.8
    """
    location = get_geolocation(ip)
    
    if location is None:
        click.echo(f"❌ Failed to get geolocation for {ip}")
        return
    
    if json_output:
        click.echo(json.dumps(location.to_dict(), indent=2))
    else:
        click.echo(f"\n🌍 IP Geolocation for {ip}")
        click.echo("=" * 60)
        click.echo(f"  📍 City: {location.city or 'N/A'}")
        click.echo(f"  📍 Region: {location.region or 'N/A'}")
        click.echo(f"  📍 Country: {location.country or 'N/A'}")
        click.echo(f"  📮 Postal: {location.postal or 'N/A'}")
        click.echo(f"  🏢 ISP: {location.org or 'N/A'}")
        click.echo(f"  ⏰ Timezone: {location.timezone or 'N/A'}")
        
        if location.latitude and location.longitude:
            click.echo(f"\n📐 Coordinates:")
            click.echo(f"  Latitude: {location.latitude}")
            click.echo(f"  Longitude: {location.longitude}")
            click.echo(f"\n🗺️ Map Links:")
            click.echo(f"  🔗 Google Maps: {location.google_maps_url}")
            click.echo(f"  🔗 Google Earth: {location.google_earth_url}")


@osint_cli.command(name="search-urls")
@click.argument("ip")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def search_urls_command(ip: str, json_output: bool):
    """Generate search engine investigation URLs for an IP.
    
    Example: gridland osint search-urls 192.168.1.1
    """
    urls = get_search_urls(ip)
    
    if json_output:
        click.echo(json.dumps({"ip": ip, "urls": urls}, indent=2))
    else:
        click.echo(f"\n🔎 Search Engine URLs for {ip}")
        click.echo("=" * 60)
        for name, url in urls.items():
            click.echo(f"  🔗 {name.title()}: {url}")


@osint_cli.command(name="full")
@click.argument("ip")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def full_report_command(ip: str, json_output: bool):
    """Generate full OSINT report for an IP address.
    
    Example: gridland osint full 192.168.1.1
    """
    report = osint_report(ip)
    
    if json_output:
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo(f"\n📊 Full OSINT Report for {ip}")
        click.echo("=" * 60)
        
        # Geolocation
        geo = report.get("geolocation")
        if geo:
            click.echo(f"\n🌍 GEOLOCATION")
            click.echo(f"  📍 Location: {geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}, {geo.get('country', 'N/A')}")
            click.echo(f"  🏢 ISP: {geo.get('org', 'N/A')}")
            if geo.get("google_maps_url"):
                click.echo(f"  🗺️ Maps: {geo['google_maps_url']}")
        else:
            click.echo(f"\n🌍 GEOLOCATION: Unable to retrieve")
        
        # Search URLs
        click.echo(f"\n🔎 SEARCH ENGINES")
        urls = report.get("search_engine_urls", {}).get("urls", {})
        for name, url in urls.items():
            click.echo(f"  🔗 {name.title()}: {url}")
        
        # Top dorks
        click.echo(f"\n🔍 TOP GOOGLE DORKS (showing first 5)")
        dorks = report.get("google_dorks", [])[:5]
        for dork in dorks:
            click.echo(f"  📝 {dork['query']}")
            click.echo(f"     {dork['url']}")


# Export for main CLI
__all__ = ["osint_cli"]
