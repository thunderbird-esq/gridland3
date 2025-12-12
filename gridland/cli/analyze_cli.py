"""
Analysis CLI for GRIDLAND Phase 3.

Command-line interface for the revolutionary analysis engine with
PhD-level performance optimizations and zero-waste resource utilization.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from tabulate import tabulate

from ..analyze import (
    AnalysisConfiguration,
    AnalysisEngine,
    AnalysisTarget,
    StreamResult,
    VulnerabilityResult,
    analyze_discovery_results,
    create_analysis_config,
    get_memory_pool,
    get_plugin_manager,
    get_scheduler,
    get_signature_database,
)
from ..analyze.core import BrandDetector, CVELookup
from ..analyze.core.osint import GeoLookup, OSINTURLGenerator
from ..analyze.plugins.builtin.credential_tester import CredentialTester
from ..analyze.plugins.builtin.login_scanner import LoginPageScanner
from ..core import IPValidator
from ..core.config import get_config
from ..core.logger import get_logger, set_verbose

logger = get_logger(__name__)


class ProgressIndicator:
    """Advanced progress indicator for analysis operations."""

    def __init__(self, message: str, show_spinner: bool = True):
        self.message = message
        self.show_spinner = show_spinner
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_idx = 0
        self.start_time = None
        self.last_update = 0
        self.targets_processed = 0
        self.total_targets = 0

    def __enter__(self):
        self.start_time = time.time()
        if self.show_spinner:
            print(f"{self.spinner_chars[0]} {self.message}", end="", flush=True, file=sys.stderr)
        else:
            print(f"⏳ {self.message}", file=sys.stderr)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            if self.show_spinner:
                print(f"\r✅ {self.message} (completed in {duration:.1f}s)", file=sys.stderr)
            else:
                print(f"✅ Completed in {duration:.1f}s", file=sys.stderr)

    def update(self, processed: int = None, total: int = None, status: str = None):
        """Update progress with counts and status."""
        if not self.show_spinner:
            return

        current_time = time.time()
        if current_time - self.last_update < 0.2:  # Throttle updates
            return

        if processed is not None:
            self.targets_processed = processed
        if total is not None:
            self.total_targets = total

        self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)

        # Build status message
        if self.total_targets > 0:
            progress = f"[{self.targets_processed}/{self.total_targets}]"
            rate = (
                self.targets_processed / (current_time - self.start_time)
                if current_time > self.start_time
                else 0
            )
            rate_str = f" {rate:.1f}/s" if rate > 0 else ""
            display_message = f"{self.message} {progress}{rate_str}"
        else:
            display_message = status or self.message

        print(
            f"\r{self.spinner_chars[self.spinner_idx]} {display_message}",
            end="",
            flush=True,
            file=sys.stderr,
        )
        self.last_update = current_time


@click.command()
@click.option(
    "--targets", "-t", help="Comma-separated IP:port pairs (e.g., 192.168.1.1:80,192.168.1.2:443)"
)
@click.option(
    "--input-file",
    "-f",
    help="Input file with targets (JSON from discovery or one IP:port per line)",
)
@click.option("--discovery-results", help="JSON file with discovery results from gl-discover")
@click.option(
    "--performance-mode",
    type=click.Choice(["FAST", "BALANCED", "THOROUGH"]),
    default="BALANCED",
    help="Analysis performance mode (default: BALANCED)",
)
@click.option(
    "--max-concurrent", type=int, help="Maximum concurrent analysis targets (default: auto)"
)
@click.option(
    "--timeout", type=float, default=30.0, help="Timeout per target in seconds (default: 30.0)"
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.7,
    help="Minimum confidence threshold for vulnerabilities (default: 0.7)",
)
@click.option("--disable-vulnerabilities", is_flag=True, help="Disable vulnerability scanning")
@click.option("--disable-streams", is_flag=True, help="Disable stream analysis")
@click.option("--disable-plugins", is_flag=True, help="Disable plugin-based scanning")
@click.option("--enrich", is_flag=True, help="Enable enrichment plugins (e.g., IP context)")
@click.option("--output", "-o", help="Output file path (JSON format)")
@click.option(
    "--output-format",
    type=click.Choice(["table", "json", "csv", "summary"]),
    default="table",
    help="Output format (default: table)",
)
@click.option("--show-statistics", is_flag=True, help="Show detailed performance statistics")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--dry-run", is_flag=True, help="Show what would be analyzed without executing")
@click.option(
    "--show-search-urls", is_flag=True, help="Show OSINT search URLs (Shodan, Censys, ZoomEye)"
)
@click.option("--geo-lookup", is_flag=True, help="Perform IP geolocation lookup")
@click.option("--google-dorks", is_flag=True, help="Generate Google dork queries")
@click.option("--show-cves", is_flag=True, help="Show CVEs for detected camera brand")
@click.option("--detect-brand", is_flag=True, help="Detect camera brand from responses")
@click.option("--scan-logins", is_flag=True, help="Scan for login pages")
@click.option(
    "--test-credentials", is_flag=True, help="Test default credentials (requires consent)"
)
@click.option("--full-scan", is_flag=True, help="Enable all reconnaissance features")
def analyze(
    targets,
    input_file,
    discovery_results,
    performance_mode,
    max_concurrent,
    timeout,
    confidence_threshold,
    disable_vulnerabilities,
    disable_streams,
    disable_plugins,
    enrich,
    output,
    output_format,
    show_statistics,
    verbose,
    dry_run,
    show_search_urls,
    geo_lookup,
    google_dorks,
    show_cves,
    detect_brand,
    scan_logins,
    test_credentials,
    full_scan,
):
    """
    Analyze targets for vulnerabilities and streams using the revolutionary Phase 3 engine.

    Examples:

      # Analyze specific targets with IP context enrichment
      gl-analyze --targets "192.168.1.100:80" --enrich

      # Analyze discovery results
      gl-analyze --discovery-results discovery_output.json --performance-mode THOROUGH

      # Fast analysis with custom settings
      gl-analyze --input-file targets.txt --performance-mode FAST --max-concurrent 200

      # Stream-only analysis
      gl-analyze --targets "192.168.1.0/24:554" --disable-vulnerabilities --disable-plugins
    """
    # Setup
    config = get_config()
    if verbose:
        set_verbose(True)

    logger.info("GRIDLAND Analysis Engine Phase 3 starting")

    # Parse and validate inputs
    analysis_targets = []

    try:
        if discovery_results:
            analysis_targets = _load_discovery_results(discovery_results)
        elif input_file:
            analysis_targets = _load_targets_from_file(input_file)
        elif targets:
            analysis_targets = _parse_target_list(targets)
        else:
            logger.error("Must specify --targets, --input-file, or --discovery-results")
            sys.exit(1)

        if not analysis_targets:
            logger.error("No valid targets found")
            sys.exit(1)

        logger.info(f"Loaded {len(analysis_targets)} targets for analysis")

    except Exception as e:
        logger.error(f"Failed to load targets: {e}")
        sys.exit(1)

    # Create analysis configuration
    analysis_config = create_analysis_config(performance_mode)

    # Apply CLI overrides
    if max_concurrent:
        analysis_config.max_concurrent_targets = max_concurrent
    if timeout:
        analysis_config.timeout_per_target = timeout
    if confidence_threshold:
        analysis_config.signature_confidence_threshold = confidence_threshold

    # Apply feature toggles
    analysis_config.enable_vulnerability_scanning = not disable_vulnerabilities
    analysis_config.enable_stream_analysis = not disable_streams
    analysis_config.enable_plugin_scanning = not disable_plugins
    analysis_config.enable_enrichment_plugins = enrich

    # Handle --full-scan convenience flag
    if full_scan:
        show_search_urls = True
        geo_lookup = True
        google_dorks = True
        show_cves = True
        detect_brand = True
        scan_logins = True
        # Note: test_credentials still requires explicit flag for safety

    if dry_run:
        _show_dry_run(analysis_targets, analysis_config)
        return

    # Execute analysis
    try:
        results = asyncio.run(_run_analysis(analysis_targets, analysis_config, verbose))

        # Output results
        _output_results(results, output, output_format, analysis_targets)

        # Run OSINT reconnaissance if any flags enabled
        if any(
            [
                show_search_urls,
                geo_lookup,
                google_dorks,
                show_cves,
                detect_brand,
                scan_logins,
                test_credentials,
            ]
        ):
            _run_osint_reconnaissance(
                analysis_targets,
                show_search_urls,
                geo_lookup,
                google_dorks,
                show_cves,
                detect_brand,
                scan_logins,
                test_credentials,
                verbose,
            )

        # Show statistics if requested
        if show_statistics:
            _show_performance_statistics()

        # Summary
        vuln_count = sum(len(r.vulnerabilities) for r in results)
        stream_count = sum(len(r.streams) for r in results)

        logger.info(
            f"Analysis completed: {len(results)} targets, {vuln_count} vulnerabilities, {stream_count} streams"
        )

    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


async def _run_analysis(
    targets: list[AnalysisTarget], config: AnalysisConfiguration, verbose: bool = False
) -> list[Any]:
    """Run the analysis engine with progress tracking."""
    engine = AnalysisEngine(config)

    try:
        with ProgressIndicator("Analyzing targets", show_spinner=not verbose) as progress:
            progress.total_targets = len(targets)

            # For progress tracking, we'll analyze in smaller batches
            batch_size = min(50, config.max_concurrent_targets)
            all_results = []

            for i in range(0, len(targets), batch_size):
                batch = targets[i : i + batch_size]
                batch_results = await engine.analyze_targets(batch)
                all_results.extend(batch_results)

                progress.update(processed=len(all_results))

        return all_results

    finally:
        await engine.shutdown()


def _load_discovery_results(file_path: str) -> list[AnalysisTarget]:
    """Load targets from discovery results JSON."""
    targets = []

    try:
        with open(file_path) as f:
            data = json.load(f)

        # Handle different JSON formats
        if isinstance(data, list):
            # Direct list of results
            results = data
        elif isinstance(data, dict) and "results" in data:
            # Wrapped in results key
            results = data["results"]
        else:
            results = [data]  # Single result

        for result in results:
            if not isinstance(result, dict):
                continue

            ip = result.get("ip", "")
            port = result.get("port", 0)

            if ip and port:
                target = AnalysisTarget(
                    ip=ip,
                    port=port,
                    service=result.get("service", ""),
                    banner=result.get("banner", ""),
                    metadata=result,
                )
                targets.append(target)

        return targets

    except Exception as e:
        logger.error(f"Failed to load discovery results from {file_path}: {e}")
        return []


def _load_targets_from_file(file_path: str) -> list[AnalysisTarget]:
    """Load targets from file (one IP:port per line or JSON)."""
    targets = []

    try:
        with open(file_path) as f:
            content = f.read().strip()

        # Try JSON first
        try:
            json_data = json.loads(content)
            return _load_discovery_results(file_path)  # Reuse JSON loading logic
        except json.JSONDecodeError:
            pass

        # Try line-by-line format
        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            try:
                if ":" in line:
                    ip, port_str = line.split(":", 1)
                    port = int(port_str)

                    target = AnalysisTarget(ip=ip.strip(), port=port)
                    targets.append(target)
                else:
                    logger.warning(f"Invalid target format on line {line_num}: {line}")

            except ValueError as e:
                logger.warning(f"Failed to parse line {line_num}: {line} - {e}")

        return targets

    except Exception as e:
        logger.error(f"Failed to load targets from {file_path}: {e}")
        return []


def _parse_target_list(target_string: str) -> list[AnalysisTarget]:
    """Parse comma-separated target list."""
    targets = []

    for target_spec in target_string.split(","):
        target_spec = target_spec.strip()

        if ":" not in target_spec:
            logger.warning(f"Invalid target format: {target_spec} (expected IP:port)")
            continue

        try:
            ip, port_str = target_spec.split(":", 1)
            port = int(port_str)

            target = AnalysisTarget(ip=ip.strip(), port=port)
            targets.append(target)

        except ValueError as e:
            logger.warning(f"Failed to parse target: {target_spec} - {e}")

    return targets


def _show_dry_run(targets: list[AnalysisTarget], config: AnalysisConfiguration):
    """Show what would be analyzed without running."""
    print("GRIDLAND Analysis - Dry Run Mode")
    print("=" * 50)
    print(f"Targets to analyze: {len(targets)}")
    print(f"Performance mode: {config.performance_mode}")
    print(f"Max concurrent: {config.max_concurrent_targets}")
    print(f"Timeout per target: {config.timeout_per_target}s")
    print(f"Confidence threshold: {config.signature_confidence_threshold}")
    print()

    print("Analysis features:")
    print(
        f"  ✓ Vulnerability scanning: {'enabled' if config.enable_vulnerability_scanning else 'disabled'}"
    )
    print(f"  ✓ Stream analysis: {'enabled' if config.enable_stream_analysis else 'disabled'}")
    print(f"  ✓ Plugin scanning: {'enabled' if config.enable_plugin_scanning else 'disabled'}")
    print()

    print("Sample targets:")
    for i, target in enumerate(targets[:10]):
        print(f"  {i+1}. {target.ip}:{target.port} ({target.service or 'unknown service'})")

    if len(targets) > 10:
        print(f"  ... and {len(targets) - 10} more targets")

    print("\nNo actual analysis will be performed.")


def _output_results(
    results: list[Any],
    output_file: str | None,
    output_format: str,
    targets: list[AnalysisTarget],
):
    """Output analysis results in specified format."""
    if not results:
        logger.warning("No results to output")
        return

    # Save to file if specified
    if output_file:
        try:
            output_data = [_result_to_dict(r) for r in results]
            with open(output_file, "w") as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Results saved to: {output_file}")
        except OSError as e:
            logger.error(f"Failed to save results: {e}")

    # Display results
    if output_format == "json":
        _output_json(results)
    elif output_format == "csv":
        _output_csv(results)
    elif output_format == "summary":
        _output_summary(results, targets)
    else:  # table format
        _output_table(results)


def _result_to_dict(result: Any) -> dict[str, Any]:
    """Convert analysis result to dictionary."""
    return {
        "ip": result.ip,
        "port": result.port,
        "service": result.service,
        "banner": result.banner,
        "analysis_time": result.analysis_time,
        "confidence": result.confidence,
        "vulnerabilities": [
            {
                "id": v.vulnerability_id,
                "severity": v.severity,
                "confidence": v.confidence,
                "description": v.description,
                "exploit_available": v.exploit_available,
            }
            for v in result.vulnerabilities
        ],
        "streams": [
            {
                "protocol": s.protocol,
                "url": s.stream_url,
                "codec": s.codec,
                "resolution": s.resolution,
                "accessible": s.accessible,
                "authenticated": s.authenticated,
            }
            for s in result.streams
        ],
    }


def _output_json(results: list[Any]):
    """Output results in JSON format."""
    output_data = [_result_to_dict(r) for r in results]
    print(json.dumps(output_data, indent=2))


def _output_csv(results: list[Any]):
    """Output results in CSV format."""
    print("IP,Port,Service,Vulnerabilities,Streams,Confidence,Analysis_Time")

    for result in results:
        vuln_count = len(result.vulnerabilities)
        stream_count = len(result.streams)

        print(
            f"{result.ip},{result.port},{result.service},{vuln_count},{stream_count},{result.confidence:.2f},{result.analysis_time:.2f}"
        )


def _output_summary(results: list[Any], targets: list[AnalysisTarget]):
    """Output summary statistics and next steps."""
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    total_streams = sum(len(r.streams) for r in results)
    avg_confidence = sum(r.confidence for r in results) / len(results) if results else 0
    avg_time = sum(r.analysis_time for r in results) / len(results) if results else 0

    # Vulnerability severity breakdown
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for result in results:
        for vuln in result.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

    print("GRIDLAND Analysis Summary")
    print("=" * 30)
    print(f"Targets analyzed: {len(results)}")
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"Total streams: {total_streams}")
    print(f"Average confidence: {avg_confidence:.2f}")
    print(f"Average analysis time: {avg_time:.2f}s")
    print()

    print("Vulnerability Severity Breakdown:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity}: {count}")

    print()
    print("Top Vulnerable Targets:")
    sorted_results = sorted(results, key=lambda r: len(r.vulnerabilities), reverse=True)
    for i, result in enumerate(sorted_results[:5]):
        if result.vulnerabilities:
            print(
                f"  {i+1}. {result.ip}:{result.port} - {len(result.vulnerabilities)} vulnerabilities"
            )

    # Next Steps / Recon Links
    unique_ips = sorted(list({t.ip for t in targets}))
    if 0 < len(unique_ips) <= 5:
        print("\n[Next Steps] Further Reconnaissance:")
        for ip in unique_ips:
            print(f"\n  Target: {ip}")
            print(f"    - ShodanSpider: gl-discover --engine shodanspider --query 'ip:\"{ip}\"' ")
            print(f"    - Censys:       https://search.censys.io/hosts/{ip}")
            print(f"    - Google Dork:  https://www.google.com/search?q=inurl:{ip}")


def _output_table(results: list[Any]):
    """Output results in table format."""
    if not results:
        return

    # Create table data
    headers = ["IP", "Port", "Service", "Vulnerabilities", "Streams", "Confidence", "Time(s)"]
    rows = []

    for result in results:
        vuln_summary = f"{len(result.vulnerabilities)}"
        if result.vulnerabilities:
            severities = [v.severity for v in result.vulnerabilities]
            critical = severities.count("CRITICAL")
            high = severities.count("HIGH")
            if critical > 0 or high > 0:
                vuln_summary += f" (C:{critical}, H:{high})"

        stream_summary = f"{len(result.streams)}"
        if result.streams:
            accessible = sum(1 for s in result.streams if s.accessible)
            if accessible > 0:
                stream_summary += f" ({accessible} accessible)"

        rows.append(
            [
                result.ip,
                result.port,
                result.service or "unknown",
                vuln_summary,
                stream_summary,
                f"{result.confidence:.2f}",
                f"{result.analysis_time:.2f}",
            ]
        )

    # Print table
    print(tabulate(rows, headers=headers, tablefmt="grid"))
    print(f"\nTotal results: {len(results)}")


def _show_performance_statistics():
    """Show detailed performance statistics."""
    print("\nPerformance Statistics")
    print("=" * 30)

    # Memory pool stats
    memory_pool = get_memory_pool()
    pool_stats = memory_pool.get_pool_statistics()

    print("Memory Pool Performance:")
    for pool_name, stats in pool_stats.items():
        hit_rate = (
            stats.pool_hits / (stats.pool_hits + stats.pool_misses) * 100
            if (stats.pool_hits + stats.pool_misses) > 0
            else 0
        )
        print(f"  {pool_name}:")
        print(f"    Hit rate: {hit_rate:.1f}%")
        print(f"    Active objects: {stats.current_active}")
        print(f"    Peak objects: {stats.peak_active}")

    # Scheduler stats
    scheduler = get_scheduler()
    scheduler_stats = scheduler.get_statistics()

    print(f"\nTask Scheduler Performance:")
    print(f"  Active workers: {scheduler_stats['active_workers']}")
    print(f"  Tasks completed: {scheduler_stats['total_tasks_completed']}")
    if "recent_performance" in scheduler_stats:
        perf = scheduler_stats["recent_performance"]
        print(f"  Success rate: {perf['success_rate']:.1%}")
        print(f"  Tasks/second: {perf['tasks_per_second']:.1f}")

    # Signature database stats
    sig_db = get_signature_database()
    db_stats = sig_db.get_statistics()

    print(f"\nSignature Database:")
    print(f"  Total signatures: {db_stats['total_signatures']}")
    print(f"  Unique ports: {db_stats['unique_ports']}")
    print(f"  Unique services: {db_stats['unique_services']}")

    # Plugin manager stats
    plugin_mgr = get_plugin_manager()
    plugin_stats = plugin_mgr.get_plugin_statistics()

    print(f"\nPlugin System:")
    print(f"  Total plugins: {plugin_stats['total_plugins']}")
    print(f"  Enabled plugins: {plugin_stats['enabled_plugins']}")
    for plugin_type, count in plugin_stats["plugins_by_type"].items():
        if count > 0:
            print(f"  {plugin_type} plugins: {count}")


def _run_osint_reconnaissance(
    targets: list,
    show_search_urls: bool,
    geo_lookup: bool,
    google_dorks: bool,
    show_cves: bool,
    detect_brand: bool,
    scan_logins: bool,
    test_credentials: bool,
    verbose: bool,
):
    """Run OSINT and reconnaissance features on targets."""
    import asyncio

    unique_ips = sorted(list({t.ip for t in targets}))

    if not unique_ips:
        logger.warning("No valid IPs for reconnaissance")
        return

    print("\n" + "=" * 60)
    print("GRIDLAND OSINT & Reconnaissance Results")
    print("=" * 60)

    for ip in unique_ips[:10]:  # Limit to first 10 IPs
        print(f"\n🎯 Target: {ip}")
        print("-" * 40)

        # IP Validation
        is_valid, warning = IPValidator.validate_ip(ip)
        if warning:
            print(f"⚠️  {warning}")

        # OSINT Search URLs
        if show_search_urls:
            print("\n📡 OSINT Search URLs:")
            urls = OSINTURLGenerator.generate_search_urls(ip)
            for platform, url in urls.items():
                print(f"   {platform.capitalize()}: {url}")

        # Google Dorks
        if google_dorks:
            print("\n🔍 Google Dork Queries:")
            dorks = OSINTURLGenerator.generate_google_dorks(ip)
            for dork in dorks[:4]:  # Show top 4 dorks
                print(f"   • {dork['query']}")
                print(f"     URL: {dork['url']}")

        # Geo Lookup (async)
        if geo_lookup:
            print("\n🌍 Geolocation:")
            try:
                geo = GeoLookup(cache_duration=3600, rate_limit_delay=0.1)
                ip_info = asyncio.run(geo.get_ip_info(ip))
                if ip_info:
                    print(f"   City: {ip_info.get('city', 'N/A')}")
                    print(f"   Region: {ip_info.get('region', 'N/A')}")
                    print(f"   Country: {ip_info.get('country', 'N/A')}")
                    print(f"   Organization: {ip_info.get('org', 'N/A')}")
                    map_urls = GeoLookup.generate_map_urls(ip_info)
                    if map_urls.get("openstreetmap"):
                        print(f"   Map: {map_urls['openstreetmap']}")
            except Exception as e:
                print(f"   ⚠️  Geo lookup failed: {e}")

        # Brand Detection
        if detect_brand:
            print("\n🏭 Brand Detection:")
            try:
                detector = BrandDetector()
                # Get open ports for this IP from targets
                ip_ports = [t.port for t in targets if t.ip == ip]
                if ip_ports:
                    # Create mock port data for detection
                    ports_data = [
                        {"port": p, "server_header": "", "content_type": "", "response_body": ""}
                        for p in ip_ports
                    ]
                    result = detector.analyze_all_ports(ports_data)
                    print(f"   Brand: {result.get('brand', 'Unknown')}")
                    print(f"   Confidence: {result.get('confidence', 0):.1%}")
                    if result.get("evidence"):
                        print(f"   Evidence: {', '.join(result['evidence'][:2])}")
            except Exception as e:
                print(f"   ⚠️  Brand detection failed: {e}")

        # CVE Lookup
        if show_cves and detect_brand:
            print("\n🔓 Known CVEs:")
            try:
                lookup = CVELookup()
                if "result" in dir() and result.get("brand") and result["brand"] != "generic":
                    cves = lookup.get_cves(result["brand"], min_severity="high")
                    if cves:
                        for cve in cves[:5]:  # Show top 5
                            print(f"   • {cve['cve_id']} ({cve['severity'].upper()})")
                            nvd_urls = lookup.generate_nvd_urls([cve])
                            if nvd_urls:
                                print(f"     {nvd_urls[0]}")
                    else:
                        print("   No high-severity CVEs found for this brand")
                else:
                    print("   (Brand detection required for CVE lookup)")
            except Exception as e:
                print(f"   ⚠️  CVE lookup failed: {e}")

        # Login Page Scanning
        if scan_logins:
            print("\n🔐 Login Page Discovery:")
            try:
                scanner = LoginPageScanner()
                ip_ports = [t.port for t in targets if t.ip == ip]
                if ip_ports:
                    result = scanner.scan_login_pages(ip, ip_ports)
                    if result.get("login_pages"):
                        for page in result["login_pages"][:5]:
                            print(f"   • {page['url']}")
                            print(
                                f"     Auth: {page.get('auth_type', 'unknown')}, Status: {page.get('status_code', 'N/A')}"
                            )
                    else:
                        print("   No login pages found")
            except Exception as e:
                print(f"   ⚠️  Login scanning failed: {e}")

        # Credential Testing (with consent warning)
        if test_credentials:
            print("\n🔑 Default Credential Testing:")
            print("   ⚠️  WARNING: Only test credentials on systems you own or have authorization!")
            try:
                tester = CredentialTester(rate_limit_delay=0.5, max_attempts_per_target=10)
                ip_ports = [t.port for t in targets if t.ip == ip]
                if ip_ports:
                    result = tester.test_default_credentials(ip, ip_ports)
                    if result.get("success"):
                        creds = result["credentials"]
                        print(f"   ✅ Valid credentials found!")
                        print(f"      URL: {creds.get('url', 'N/A')}")
                        print(f"      Username: {creds.get('username', 'N/A')}")
                        print(f"      Auth Type: {creds.get('auth_type', 'N/A')}")
                    else:
                        print(
                            f"   No default credentials found (tested {result.get('attempts_made', 0)} combinations)"
                        )
            except Exception as e:
                print(f"   ⚠️  Credential testing failed: {e}")

    if len(unique_ips) > 10:
        print(f"\n... and {len(unique_ips) - 10} more targets")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    analyze()
