import os
from typing import List, Dict, Any, Optional

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.core.models import VulnerabilityResult
from gridland.core.config import get_config
from gridland.core.logger import get_logger

logger = get_logger(__name__)

class MetasploitPlugin(VulnerabilityPlugin):
    """
    Generates Metasploit Framework resource scripts for exploitable CVEs.
    """

    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Metasploit RC Script Generator",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="reporting",
            supported_services=[],
            supported_ports=[],
            description="Generates Metasploit .rc scripts for known exploitable CVEs."
        )
        self.cve_to_module_map = {
            "CVE-2017-7921": "exploit/multi/http/hikvision_auth_bypass",
            "CVE-2021-36260": "exploit/linux/http/hikvision_cmd_injection",
            # Add more mappings here
        }


    def generate_rc_script(self, vulnerability: VulnerabilityResult) -> Optional[str]:
        """
        Generates the content for a Metasploit .rc file.
        """
        module = self.cve_to_module_map.get(vulnerability.vulnerability_id)
        if not module:
            return None

        rhost = vulnerability.ip
        rport = vulnerability.port

        script_content = f"use {module}\n"
        script_content += f"set RHOSTS {rhost}\n"
        if rport:
            script_content += f"set RPORT {rport}\n"
        script_content += "run\n"

        return script_content

    async def analyze(self, target_ip: str, target_port: int,
                     service: str = "", banner: str = "",
                     existing_results: List[VulnerabilityResult] = None) -> List[VulnerabilityResult]:
        """
        Analyzes existing vulnerability results to generate Metasploit scripts.
        NOTE: The plugin architecture does not currently support passing existing_results.
              This method is designed for a future-state or post-processing engine.
        """
        results = []
        if not existing_results:
            return results

        config = get_config()
        output_dir = config.output.get('metasploit_scripts', 'metasploit')
        os.makedirs(output_dir, exist_ok=True)

        for vuln in existing_results:
            if vuln.vulnerability_id in self.cve_to_module_map:
                rc_content = self.generate_rc_script(vuln)
                if rc_content:
                    filename = f"{vuln.vulnerability_id}_{vuln.ip}.rc"
                    filepath = os.path.join(output_dir, filename)
                    try:
                        with open(filepath, 'w') as f:
                            f.write(rc_content)
                        logger.info(f"Metasploit RC script saved to {filepath}")
                        # Create a new result to track the generated file
                        report_vuln = self.memory_pool.acquire_vulnerability_result()
                        report_vuln.ip = target_ip
                        report_vuln.port = target_port
                        report_vuln.vulnerability_id = "METASPLOIT-SCRIPT-GENERATED"
                        report_vuln.severity = "INFO"
                        report_vuln.description = f"Metasploit script generated for {vuln.vulnerability_id}"
                        report_vuln.metadata = {'rc_file_path': filepath}
                        results.append(report_vuln)
                    except IOError as e:
                        logger.error(f"Failed to write RC script to {filepath}: {e}")

        return results

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                 service: str, banner: str) -> List[Any]:
        # This plugin does not scan targets directly. It's intended to be used
        # in a post-processing step that provides the list of found vulnerabilities.
        # Returning an empty list to satisfy the abstract method requirement.
        return []
