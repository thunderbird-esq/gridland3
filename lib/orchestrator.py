"""
Scan orchestration functions for Gridland web interface
"""
import ipaddress
from typing import List
from .core import ScanTarget
from .network import scan_ports
from .identify import identify_device
from .jobs import get_job, update_job_status, add_job_log, set_job_results, update_job_progress
from concurrent.futures import ThreadPoolExecutor, TimeoutError

# Comprehensive camera port list - Prioritized for speed (685 unique ports)
# High-priority ports are listed first.
PRIORITY_PORTS = [
    80, 443, 8080, 8443, 554, 8554, 8000, 37777, 8008, 5000, 9000, 8888,
]

# The rest of the ports, with duplicates removed and sorted.
OTHER_PORTS = [
    1554, 1755, 1756, 1757, 1758, 1759, 1760, 1935, 1936, 1937, 1938, 1939,
    2554, 3554, 3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
    37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787,
    37788, 37789, 37790, 37791, 37792, 37793, 37794, 37795, 37796, 37797,
    37798, 37799, 37800, 4554, 5001, 5002, 5003, 5004, 5005, 5006, 5007,
    5008, 5009, 5010, 5554, 6000, 6001, 6002, 6003, 6004, 6005, 6006,
    6007, 6008, 6009, 6010, 6554, 7000, 7001, 7002, 7003, 7004, 7005,
    7006, 7007, 7008, 7009, 7010, 7554, 8001, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095,
    8096, 8097, 8098, 8099, 8100, 8110, 8120, 8130, 8140, 8150, 8160,
    8170, 8180, 8190, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896,
    8897, 8898, 8899, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008,
    9009, 9010, 9554, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997,
    9998, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007,
    10008, 10009, 10010, 10554, 11000, 11001, 11002, 11003, 11004, 11005,
    11006, 11007, 11008, 11009, 11010, 12000, 12001, 12002, 12003, 12004,
    12005, 12006, 12007, 12008, 12009, 12010, 13000, 13001, 13002, 13003,
    13004, 13005, 13006, 13007, 13008, 13009, 13010, 14000, 14001, 14002,
    14003, 14004, 14005, 14006, 14007, 14008, 14009, 14010, 15000, 15001,
    15002, 15003, 15004, 15005, 15006, 15007, 15008, 15009, 15010, 20000,
    20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010,
    21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009,
    21010, 22000, 22001, 22002, 22003, 22004, 22005, 22006, 22007, 22008,
    22009, 22010, 23000, 23001, 23002, 23003, 23004, 23005, 23006, 23007,
    23008, 23009, 23010, 24000, 24001, 24002, 24003, 24004, 24005, 24006,
    24007, 24008, 24009, 24010, 25000, 25001, 25002, 25003, 25004, 25005,
    25006, 25007, 25008, 25009, 25010, 30000, 30001, 30002, 30003, 30004,
    30005, 30006, 30007, 30008, 30009, 30010, 31000, 31001, 31002, 31003,
    31004, 31005, 31006, 31007, 31008, 31009, 31010, 32000, 32001, 32002,
    32003, 32004, 32005, 32006, 32007, 32008, 32009, 32010, 33000, 33001,
    33002, 33003, 33004, 33005, 33006, 33007, 33008, 33009, 33010, 34000,
    34001, 34002, 34003, 34004, 34005, 34006, 34007, 34008, 34009, 34010,
    35000, 35001, 35002, 35003, 35004, 35005, 35006, 35007, 35008, 35009,
    35010, 36000, 36001, 36002, 36003, 36004, 36005, 36006, 36007, 36008,
    36009, 36010, 37000, 37001, 37002, 37003, 37004, 37005, 37006, 37007,
    37008, 37009, 37010, 38000, 38001, 38002, 38003, 38004, 38005, 38006,
    38007, 38008, 38009, 38010, 39000, 39001, 39002, 39003, 39004, 39005,
    39006, 39007, 39008, 39009, 39010, 40000, 40001, 40002, 40003, 40004,
    40005, 40006, 40007, 40008, 40009, 40010, 41000, 41001, 41002, 41003,
    41004, 41005, 41006, 41007, 41008, 41009, 41010, 42000, 42001, 42002,
    42003, 42004, 42005, 42006, 42007, 42008, 42009, 42010, 43000, 43001,
    43002, 43003, 43004, 43005, 43006, 43007, 43008, 43009, 43010, 44000,
    44001, 44002, 44003, 44004, 44005, 44006, 44007, 44008, 44009, 44010,
    45000, 45001, 45002, 45003, 45004, 45005, 45006, 45007, 45008, 45009,
    45010, 46000, 46001, 46002, 46003, 46004, 46005, 46006, 46007, 46008,
    46009, 46010, 47000, 47001, 47002, 47003, 47004, 47005, 47006, 47007,
    47008, 47009, 47010, 48000, 48001, 48002, 48003, 48004, 48005, 48006,
    48007, 48008, 48009, 48010, 49000, 49001, 49002, 49003, 49004, 49005,
    49006, 49007, 49008, 49009, 49010, 50000, 50001, 50002, 50003, 50004,
    50005, 50006, 50007, 50008, 50009, 50010, 51000, 51001, 51002, 51003,
    51004, 51005, 51006, 51007, 51008, 51009, 51010, 52000, 52001, 52002,
    52003, 52004, 52005, 52006, 52007, 52008, 52009, 52010, 53000, 53001,
    53002, 53003, 53004, 53005, 53006, 53007, 53008, 53009, 53010, 54000,
    54001, 54002, 54003, 54004, 54005, 54006, 54007, 54008, 54009, 54010,
    55000, 55001, 55002, 55003, 55004, 55005, 55006, 55007, 55008, 55009,
    55010, 56000, 56001, 56002, 56003, 56004, 56005, 56006, 56007, 56008,
    56009, 56010, 57000, 57001, 57002, 57003, 57004, 57005, 57006, 57007,
    57008, 57009, 57010, 58000, 58001, 58002, 58003, 58004, 58005, 58006,
    58007, 58008, 58009, 58010, 59000, 59001, 59002, 59003, 59004, 59005,
    59006, 59007, 59008, 59009, 59010, 60000, 60001, 60002, 60003, 60004,
    60005, 60006, 60007, 60008, 60009, 60010, 61000, 61001, 61002, 61003,
    61004, 61005, 61006, 61007, 61008, 61009, 61010, 62000, 62001, 62002,
    62003, 62004, 62005, 62006, 62007, 62008, 62009, 62010, 63000, 63001,
    63002, 63003, 63004, 63005, 63006, 63007, 63008, 63009, 63010, 64000,
    64001, 64002, 64003, 64004, 64005, 64006, 64007, 64008, 64009, 64010,
    65000, 65001, 65002, 65003, 65004, 65005, 65006, 65007, 65008, 65009,
    65010
]

CAMERA_PORTS = PRIORITY_PORTS + [p for p in OTHER_PORTS if p not in PRIORITY_PORTS]


def run_scan(job_id: str, target: str, aggressive: bool = False, threads: int = 100, timeout: int = 300) -> None:
    """
    Run a scan against a target and update the job with results
    
    Args:
        job_id: Job identifier
        target: Target IP or network range
        aggressive: Whether to run aggressive scans (credentials, streams)
        threads: Number of scanning threads
        timeout: Timeout in seconds for a single host scan
    """
    job = get_job(job_id)
    if not job:
        return
    
    try:
        update_job_status(job_id, "running")
        add_job_log(job_id, f"Starting scan of {target}")
        
        results = []
        
        # Determine if target is single IP or network range
        ips_to_scan = []
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips_to_scan = [str(ip) for ip in network.hosts()]
                add_job_log(job_id, f"Scanning {len(ips_to_scan)} hosts in network range: {target}")
            except ValueError as e:
                add_job_log(job_id, f"Invalid network range: {e}")
                update_job_status(job_id, "failed")
                return
        else:
            ips_to_scan.append(target)
            add_job_log(job_id, f"Scanning single target: {target}")

        with ThreadPoolExecutor(max_workers=1) as executor:
            for ip in ips_to_scan:
                future = executor.submit(_scan_single_target, job_id, ip, aggressive, threads)
                try:
                    result = future.result(timeout=timeout)
                    if result:
                        results.append(result)
                        add_job_log(job_id, f"Found device at {ip}: {result.device_type or 'Unknown'} ({len(result.open_ports)} ports)")
                except TimeoutError:
                    add_job_log(job_id, f"Scan for {ip} timed out after {timeout} seconds.")
                except Exception as e:
                    add_job_log(job_id, f"Error scanning {ip}: {e}")
        
        # Update job with results
        set_job_results(job_id, results)
        
        if results:
            add_job_log(job_id, f"Scan completed - found {len(results)} devices")
        else:
            add_job_log(job_id, "Scan completed - no devices found")
        
        update_job_status(job_id, "completed")
        
    except Exception as e:
        add_job_log(job_id, f"Scan failed: {str(e)}")
        update_job_status(job_id, "failed")


def _scan_single_target(job_id: str, ip: str, aggressive: bool, threads: int) -> ScanTarget:
    """
    Scan a single target IP
    
    Args:
        job_id: Job identifier for logging
        ip: Target IP address
        aggressive: Whether to run aggressive scans
        threads: Number of scanning threads
        
    Returns:
        ScanTarget: Scan results if target has open ports, None otherwise
    """
    target = ScanTarget(ip=ip)
    
    # Step 1: Port scan
    update_job_progress(job_id, 5, f"Port scanning {ip}...")
    target.open_ports = scan_ports(ip, CAMERA_PORTS, max_threads=threads)
    
    if not target.open_ports:
        add_job_log(job_id, f"No open ports found on {ip}")
        return None
    
    add_job_log(job_id, f"Found {len(target.open_ports)} open ports on {ip}")
    
    # Step 2: Device identification
    update_job_progress(job_id, 15, f"Identifying device at {ip}...")
    target.device_type, target.brand = identify_device(ip, target.open_ports)
    
    if target.device_type:
        add_job_log(job_id, f"Identified {ip} as {target.device_type} ({target.brand})")
    else:
        add_job_log(job_id, f"Could not identify device type for {ip}")
    
    if aggressive:
        update_job_progress(job_id, 30, f"Running aggressive scans on {ip}...")
        
        # Define progress callback
        def progress_callback(plugin_name, plugin_progress, plugin_message):
            # Scale plugin progress (30-90%)
            total_progress = 30 + int(plugin_progress * 0.6)
            update_job_progress(job_id, total_progress, f"[{plugin_name}] {plugin_message}")

        # Import and run plugins
        try:
            from .plugin_manager import PluginManager
            manager = PluginManager()
            findings = manager.run_all_plugins(target, progress_callback)
            
            # Process findings and add to target
            for finding in findings:
                add_job_log(job_id, f"Found: {finding.category} - {finding.description}")
                
                if finding.category == "credential":
                    # Extract credentials from finding
                    if finding.data and "username" in finding.data and "password" in finding.data:
                        creds_key = f"{finding.data['username']}:{finding.data['password']}"
                        target.credentials[creds_key] = finding.url or f"{ip}:{finding.port}"
                
                elif finding.category == "stream":
                    # Add discovered streams
                    if finding.url:
                        target.streams.append(finding.url)
                
                else:
                    # Add other findings as vulnerabilities
                    target.vulnerabilities.append(finding.description)
                    
        except Exception as e:
            add_job_log(job_id, f"Plugin system error: {str(e)}")
        
        add_job_log(job_id, f"Aggressive scans completed for {ip}")
    
    update_job_progress(job_id, 100, "Scan complete")
    return target


def scan_single_ip(ip: str, aggressive: bool = False, threads: int = 100) -> ScanTarget:
    """
    Scan a single IP address (for CLI use)
    
    Args:
        ip: Target IP address
        aggressive: Whether to run aggressive scans
        threads: Number of scanning threads
        
    Returns:
        ScanTarget: Scan results if target has open ports, None otherwise
    """
    target = ScanTarget(ip=ip)
    
    # Step 1: Port scan
    target.open_ports = scan_ports(ip, CAMERA_PORTS, max_threads=threads)
    
    if not target.open_ports:
        return None
    
    # Step 2: Device identification
    target.device_type, target.brand = identify_device(ip, target.open_ports)
    
    if aggressive:
        # TODO: Plugin system for credential testing and stream discovery
        pass
    
    return target