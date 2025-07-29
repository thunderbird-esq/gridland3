"""
Discovery CLI for GRIDLAND.

Command-line interface for target discovery using multiple engines:
- Masscan for high-speed port scanning
- ShodanSpider v2 for internet-wide device discovery
- Censys for professional search capabilities
"""

import json
import sys
import time
from pathlib import Path
from typing import List, Optional

import click
from tabulate import tabulate

from ..core.config import get_config, get_port_manager
from ..core.logger import get_logger, set_verbose
from ..discover.masscan_engine import MasscanEngine
from ..discover.shodanspider_engine import ShodanSpiderEngine
from ..discover.censys_engine import CensysEngine

logger = get_logger(__name__)


def _get_ports_for_scan_mode(scan_mode: str, port_manager) -> List[int]:
    """Get appropriate ports based on scan mode using CameraPortManager."""
    return port_manager.get_ports_for_scan_mode(scan_mode)


class ProgressIndicator:
    """Simple progress indicator for long-running operations."""
    
    def __init__(self, message: str, show_spinner: bool = True):
        self.message = message
        self.show_spinner = show_spinner
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.spinner_idx = 0
        self.start_time = None
        self.last_update = 0
    
    def __enter__(self):
        self.start_time = time.time()
        if self.show_spinner:
            print(f"{self.spinner_chars[0]} {self.message}", end='', flush=True)
        else:
            print(f"⏳ {self.message}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            if self.show_spinner:
                print(f"\r✅ {self.message} (completed in {duration:.1f}s)")
            else:
                print(f"✅ Completed in {duration:.1f}s")
    
    def update(self, status: str = None):
        """Update progress indicator."""
        if not self.show_spinner:
            return
            
        current_time = time.time()
        if current_time - self.last_update < 0.1:  # Throttle updates
            return
            
        self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)
        display_message = status or self.message
        print(f"\r{self.spinner_chars[self.spinner_idx]} {display_message}", end='', flush=True)
        self.last_update = current_time


@click.command()
@click.option('--engine', 
              type=click.Choice(['masscan', 'shodanspider', 'censys', 'auto']), 
              default='auto',
              help='Discovery engine to use (default: auto)')
@click.option('--range', '-r',
              help='IP range to scan (CIDR notation, range, or single IP)')
@click.option('--query', '-q',
              help='Search query for ShodanSpider engine')
@click.option('--ports', '-p',
              help='Comma-separated port list (overrides scan-mode and categories)')
@click.option('--scan-mode',
              type=click.Choice(['FAST', 'BALANCED', 'COMPREHENSIVE']),
              default='BALANCED',
              help='Scan intensity: FAST (~20 ports), BALANCED (~100 ports), COMPREHENSIVE (all ports)')
@click.option('--port-categories',
              multiple=True,
              type=click.Choice(get_port_manager().get_available_categories()),
              help='Specific port categories to scan (overrides scan-mode)')
@click.option('--show-port-preview',
              is_flag=True,
              help='Display ports that will be scanned and exit')
@click.option('--rate', 
              type=int,
              help='Masscan scan rate in packets/second (default: from config)')
@click.option('--limit', '-l',
              type=int, 
              default=1000,
              help='Maximum results to return (default: 1000)')
@click.option('--country',
              help='Filter by country code (e.g., US, CN) - ShodanSpider only')
@click.option('--cve',
              help='Search for devices vulnerable to specific CVE')
@click.option('--brands',
              help='Comma-separated list of camera brands to search for')
@click.option('--cameras-only',
              is_flag=True,
              help='Filter results to likely camera candidates only')
@click.option('--output', '-o',
              help='Output file path (JSON format)')
@click.option('--output-format',
              type=click.Choice(['table', 'json', 'csv', 'xml']),
              default='table',
              help='Output format (default: table)')
@click.option('--input-file', '-f',
              help='Input file with targets (one per line)')
@click.option('--verbose', '-v',
              is_flag=True,
              help='Enable verbose logging')
@click.option('--dry-run',
              is_flag=True,
              help='Show what would be done without executing')
def discover(engine, range, query, ports, scan_mode, port_categories, show_port_preview, rate, limit, country, cve, brands,
            cameras_only, output, output_format, input_file, verbose, dry_run):
    """
    Discover camera targets using various engines.
    
    Examples:
    
      # Scan local network with masscan using balanced port coverage
      gl-discover --engine masscan --range 192.168.1.0/24 --scan-mode BALANCED

      # Scan with specific port categories
      gl-discover -r 192.168.1.0/24 --port-categories standard_web rtsp_ecosystem

      # Preview the ports for a comprehensive scan without running it
      gl-discover -r 192.168.1.0/24 --scan-mode COMPREHENSIVE --show-port-preview
      
      # Search for cameras using ShodanSpider
      gl-discover --engine shodanspider --query "camera"
      
      # Search for specific camera brands
      gl-discover --engine shodanspider --brands "hikvision,dahua"
    """
    # Setup
    config = get_config()
    if verbose:
        set_verbose(True)
    
    logger.info("GRIDLAND Discovery Engine starting")
    
    # Validate inputs
    if not _validate_inputs(engine, range, query, input_file):
        sys.exit(1)
    
    # Initialize port manager
    port_manager = get_port_manager()
    
    # Parse ports if provided, otherwise use scan mode or categories
    port_list = None
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(',')]
        except ValueError:
            logger.error(f"Invalid port specification: {ports}")
            sys.exit(1)
    elif port_categories:
        port_list = port_manager.get_ports_for_categories(list(port_categories))
        logger.info(f"Using port categories {list(port_categories)}: {len(port_list)} ports")
    else:
        port_list = port_manager.get_ports_for_scan_mode(scan_mode)
        logger.info(f"Using {scan_mode} scan mode: {len(port_list)} ports")

    if show_port_preview:
        _show_port_preview(port_list, scan_mode, port_categories, port_manager)
        return

    # Parse brands if provided
    brand_list = None
    if brands:
        brand_list = [b.strip() for b in brands.split(',')]
    
    if dry_run:
        _show_dry_run(engine, range, query, port_list, scan_mode, port_categories, rate, limit, country, cve, brand_list, input_file, port_manager)
        return
    
    # Execute discovery
    try:
        with ProgressIndicator(f"Running {engine} discovery", show_spinner=not verbose) as p:
            results = _execute_discovery(
                engine, range, query, port_list, scan_mode, port_categories, rate, limit, country,
                cve, brand_list, input_file, config
            )
        
        # Filter for cameras if requested
        if cameras_only:
            results = _filter_camera_candidates(results, engine)
        
        # Output results
        _output_results(results, output, output_format, engine)
        
        logger.info(f"Discovery completed. Found {len(results)} results.")
        
    except KeyboardInterrupt:
        logger.warning("Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        sys.exit(1)


def _validate_inputs(engine, range, query, input_file):
    """Validate command line inputs."""
    # Need at least one input source
    if not any([range, query, input_file]):
        logger.error("Must specify --range, --query, or --input-file")
        return False
    
    # Validate engine selection
    if engine == 'masscan' and not range and not input_file:
        logger.error("Masscan engine requires --range or --input-file")
        return False
    
    if engine == 'shodanspider' and not query and not input_file:
        logger.error("ShodanSpider engine requires --query or --input-file")
        return False
    
    # Validate file exists
    if input_file and not Path(input_file).exists():
        logger.error(f"Input file not found: {input_file}")
        return False
    
    return True


def _show_dry_run(engine, range, query, ports, scan_mode, port_categories, rate, limit, country, cve, brands, input_file, port_manager):
    """Show what would be executed without running."""
    print("GRIDLAND Discovery - Dry Run Mode")
    print("=" * 40)
    print(f"Engine: {engine}")
    
    if range:
        print(f"IP Range: {range}")
    if query:
        print(f"Query: {query}")
    if ports:
        print(f"Ports: {len(ports)} ports")
        if port_categories:
            print(f"Categories: {', '.join(port_categories)}")
        else:
            print(f"Scan Mode: {scan_mode}")
        
        # Show port summary using port manager
        port_summary = port_manager.summarize_port_ranges(ports)
        print(f"Port ranges: {port_summary}")
        
        # Show first few ports for reference
        print(f"Sample ports: {', '.join(map(str, ports[:15]))}")
        if len(ports) > 15:
            print(f"  ... and {len(ports) - 15} more")
    if rate:
        print(f"Rate: {rate} pps")
    if limit:
        print(f"Limit: {limit}")
    if country:
        print(f"Country: {country}")
    if cve:
        print(f"CVE: {cve}")
    if brands:
        print(f"Brands: {brands}")
    if input_file:
        print(f"Input File: {input_file}")
    
    print("\nNo actual scanning will be performed.")


def _execute_discovery(engine, range, query, ports, rate, limit, country, 
                      cve, brands, input_file, config):
    """Execute discovery based on selected engine and parameters."""
    results = []
    
    # Auto-select engine if needed
    if engine == 'auto':
        engine = _auto_select_engine(range, query, input_file)
        logger.info(f"Auto-selected engine: {engine}")
    
    if engine == 'masscan':
        results = _run_masscan_discovery(range, ports, rate, input_file, config)
    
    elif engine == 'shodanspider':
        results = _run_shodanspider_discovery(query, limit, country, cve, brands, config)
    
    elif engine == 'censys':
        results = _run_censys_discovery(query, limit, country, brands, config)
    
    else:
        logger.error(f"Unknown engine: {engine}")
        return []
    
    return results


def _auto_select_engine(range, query, input_file):
    """Automatically select the best engine for the given inputs."""
    # If we have IP range or file with IPs, use masscan
    if range or input_file:
        return 'masscan'
    
    # If we have search query, try engines in order of preference
    if query:
        config = get_config()
        
        # Try ShodanSpider first (free)
        shodanspider = ShodanSpiderEngine(config)
        if shodanspider.is_available():
            return 'shodanspider'
        
        # Try Censys if available (requires API key)
        censys = CensysEngine(config)
        if censys.is_available():
            return 'censys'
        
        # Default to shodanspider even if not available (will show error)
        return 'shodanspider'
    
    # Default fallback
    return 'masscan'


def _show_port_preview(ports: List[int], scan_mode: str, port_categories: Optional[List[str]], port_manager):
    """Display a preview of the ports to be scanned."""
    print("GRIDLAND Discovery - Port Preview")
    print("=" * 40)

    if port_categories:
        print(f"Scan using categories: {', '.join(port_categories)}")
    else:
        print(f"Scan Mode: {scan_mode}")

    print(f"Total ports to be scanned: {len(ports)}")

    port_summary = port_manager.summarize_port_ranges(ports)
    print(f"Port ranges: {port_summary}")

    # Show first few ports for reference
    print(f"Sample ports: {', '.join(map(str, ports[:20]))}")
    if len(ports) > 20:
        print(f"  ... and {len(ports) - 20} more")

    # Estimate scan time (very rough estimate)
    estimated_time = (len(ports) / 500) * 60  # Rough guess: 1 min per 500 ports
    print(f"\nEstimated scan time: ~{estimated_time:.1f} seconds (highly dependent on network)")


def _execute_discovery(engine, range, query, ports, scan_mode, port_categories, rate, limit, country,
                      cve, brands, input_file, config):
    """Execute discovery based on selected engine and parameters."""
    results = []

    # Auto-select engine if needed
    if engine == 'auto':
        engine = _auto_select_engine(range, query, input_file)
        logger.info(f"Auto-selected engine: {engine}")

    if engine == 'masscan':
        results = _run_masscan_discovery(range, ports, scan_mode, port_categories, rate, input_file, config)

    elif engine == 'shodanspider':
        results = _run_shodanspider_discovery(query, limit, country, cve, brands, config)

    elif engine == 'censys':
        results = _run_censys_discovery(query, limit, country, brands, config)

    else:
        logger.error(f"Unknown engine: {engine}")
        return []

    return results


def _run_masscan_discovery(range, ports, scan_mode, port_categories, rate, input_file, config):
    """Execute discovery using Masscan engine."""
    engine = MasscanEngine(config)
    
    if not engine.is_available():
        logger.warning("Masscan not available, using internal scanner")
    
    results = []
    
    if input_file:
        # Scan targets from file
        # Note: scan_mode and port_categories are not directly used here, ports list is passed
        results = engine.scan_targets_file(input_file, ports)
    elif range:
        # Scan IP range
        results = engine.scan_range_comprehensive(
            range,
            scan_mode=scan_mode,
            custom_categories=port_categories,
            rate=rate
        )
    
    # Convert to common format
    return [
        {
            'ip': r.ip,
            'port': r.port,
            'protocol': r.protocol,
            'service': 'unknown',
            'banner': '',
            'timestamp': r.timestamp,
            'source': 'masscan'
        }
        for r in results
    ]


def _run_shodanspider_discovery(query, limit, country, cve, brands, config):
    """Execute discovery using ShodanSpider engine."""
    engine = ShodanSpiderEngine(config)
    
    if not engine.is_available():
        logger.error("ShodanSpider v2 not available")
        return []
    
    results = []
    
    if cve:
        # CVE search
        print(f"🔍 Searching for CVE {cve}...")
        results = engine.search_by_cve(cve, limit)
    elif brands:
        # Brand search
        print(f"🏢 Searching for brands: {', '.join(brands)}...")
        results = engine.search_camera_brands(brands, limit)
    elif query:
        # General search
        search_desc = f"query '{query}'"
        if country:
            search_desc += f" in {country}"
        print(f"🌐 Searching for {search_desc}...")
        results = engine.search_cameras(query, limit, country)
    else:
        # Default camera search
        print("📹 Running default camera search...")
        results = engine.get_default_camera_search(limit)
    
    # Convert to common format
    return [
        {
            'ip': r.ip,
            'port': r.port,
            'protocol': 'tcp',
            'service': r.service,
            'banner': r.banner,
            'country': r.country,
            'org': r.org,
            'timestamp': r.timestamp,
            'vulnerabilities': r.vulnerabilities,
            'source': 'shodanspider'
        }
        for r in results
    ]


def _run_censys_discovery(query, limit, country, brands, config):
    """Execute discovery using Censys engine."""
    engine = CensysEngine(config)
    
    if not engine.is_available():
        logger.error("Censys API credentials not configured")
        return []
    
    results = []
    
    if brands:
        # Brand search
        for brand in brands:
            brand_query = f'autonomous_system.description: "{brand}" and services.port: (80 or 554 or 8080)'
            if country:
                brand_query += f' and location.country: "{country}"'
            brand_results = engine.search_hosts(brand_query, limit // len(brands))
            results.extend(brand_results)
    elif query:
        # General search
        search_query = query
        if country:
            search_query += f' and location.country: "{country}"'
        results = engine.search_hosts(search_query, limit)
    else:
        # Default camera search
        results = engine.search_cameras(limit)
    
    # Convert to common format
    return [
        {
            'ip': r.ip,
            'port': r.port,
            'protocol': r.protocol,
            'service': r.service,
            'banner': r.banner,
            'country': r.country,
            'org': r.org,
            'timestamp': r.timestamp,
            'vulnerabilities': [],  # Censys doesn't provide vuln data in basic search
            'source': 'censys'
        }
        for r in results
    ]


def _filter_camera_candidates(results, engine):
    """Filter results for likely camera candidates."""
    if engine == 'masscan':
        # Use masscan engine's filtering
        masscan_engine = MasscanEngine()
        masscan_results = [
            type('Result', (), {
                'ip': r['ip'], 
                'port': r['port'], 
                'protocol': r['protocol'],
                'timestamp': r['timestamp'],
                'status': 'open'
            })() 
            for r in results
        ]
        candidates = masscan_engine.get_camera_candidates(masscan_results)
        candidate_ips_ports = {(c.ip, c.port) for c in candidates}
        
        return [r for r in results if (r['ip'], r['port']) in candidate_ips_ports]
    
    elif engine == 'shodanspider':
        # Use shodanspider engine's filtering
        shodanspider_engine = ShodanSpiderEngine()
        shodanspider_results = [
            type('Result', (), {
                'ip': r['ip'],
                'port': r['port'],
                'service': r.get('service', ''),
                'banner': r.get('banner', ''),
                'country': r.get('country', ''),
                'org': r.get('org', ''),
                'timestamp': r.get('timestamp', ''),
                'vulnerabilities': r.get('vulnerabilities', [])
            })()
            for r in results
        ]
        candidates = shodanspider_engine.get_camera_candidates(shodanspider_results)
        candidate_ips_ports = {(c.ip, c.port) for c in candidates}
        
        return [r for r in results if (r['ip'], r['port']) in candidate_ips_ports]
    
    return results


def _output_results(results, output_file, output_format, engine):
    """Output results in specified format."""
    if not results:
        logger.warning("No results to output")
        return
    
    # Save to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to: {output_file}")
        except IOError as e:
            logger.error(f"Failed to save results: {e}")
    
    # Display results
    if output_format == 'json':
        print(json.dumps(results, indent=2))
    
    elif output_format == 'csv':
        _output_csv(results)
    
    elif output_format == 'xml':
        _output_xml(results)
    
    else:  # table format
        _output_table(results, engine)


def _output_csv(results):
    """Output results in CSV format."""
    if not results:
        return
    
    # Get all unique keys
    all_keys = set()
    for result in results:
        all_keys.update(result.keys())
    
    headers = sorted(all_keys)
    
    # Print CSV header
    print(','.join(headers))
    
    # Print CSV rows
    for result in results:
        row = []
        for header in headers:
            value = result.get(header, '')
            if isinstance(value, list):
                value = ';'.join(map(str, value))
            row.append(str(value))
        print(','.join(row))


def _output_xml(results):
    """Output results in XML format."""
    if not results:
        print("<results></results>")
        return
    
    print('<?xml version="1.0" encoding="UTF-8"?>')
    print('<results>')
    
    for result in results:
        print('  <target>')
        for key, value in result.items():
            # Handle list values (like vulnerabilities)
            if isinstance(value, list):
                print(f'    <{key}>')
                for item in value:
                    print(f'      <item>{_xml_escape(str(item))}</item>')
                print(f'    </{key}>')
            else:
                print(f'    <{key}>{_xml_escape(str(value))}</{key}>')
        print('  </target>')
    
    print('</results>')


def _xml_escape(text):
    """Escape special XML characters."""
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&apos;'))


def _output_table(results, engine):
    """Output results in table format."""
    if not results:
        return
    
    # Select columns based on engine
    if engine == 'masscan':
        headers = ['IP', 'Port', 'Protocol', 'Service']
        rows = []
        for r in results:
            rows.append([
                r['ip'],
                r['port'],
                r.get('protocol', 'tcp'),
                r.get('service', 'unknown')
            ])
    
    else:  # shodanspider
        headers = ['IP', 'Port', 'Service', 'Country', 'Organization']
        rows = []
        for r in results:
            org = r.get('org', '')
            if len(org) > 30:
                org = org[:27] + '...'
            
            rows.append([
                r['ip'],
                r['port'],
                r.get('service', 'unknown'),
                r.get('country', ''),
                org
            ])
    
    # Print table
    print(tabulate(rows, headers=headers, tablefmt='grid'))
    print(f"\nTotal results: {len(results)}")


if __name__ == '__main__':
    discover()