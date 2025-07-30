"""
Built-in Security Plugins for GRIDLAND
"""

def get_builtin_plugins():
    """
    Returns a list of all built-in plugin classes.
    This function is used by the PluginManager to discover and load plugins,
    avoiding circular import issues.
    """
    from .hikvision_scanner import HikvisionScanner
    from .dahua_scanner import DahuaScanner
    from .axis_scanner import AxisScanner
    from .banner_grabber import BannerGrabber
    from .enhanced_ip_intelligence_scanner import EnhancedIPIntelligenceScanner
    from .enhanced_camera_detector import EnhancedCameraDetector
    from .cp_plus_scanner import CPPlusScanner
    from .advanced_fingerprinting_scanner import AdvancedFingerprintingScanner
    from .cve_correlation_scanner import CVECorrelationScanner
    from .enhanced_credential_scanner import EnhancedCredentialScanner
    from .multi_protocol_stream_scanner import MultiProtocolStreamScanner
    from .osint_integration_scanner import OSINTIntegrationScanner
    from .credential_bruteforcing import CredentialBruteforcingScanner
    from .shodan_enrichment import ShodanEnrichment

    return [
        HikvisionScanner,
        DahuaScanner,
        AxisScanner,
        BannerGrabber,
        EnhancedIPIntelligenceScanner,
        EnhancedCameraDetector,
        CPPlusScanner,
        AdvancedFingerprintingScanner,
        CVECorrelationScanner,
        EnhancedCredentialScanner,
        MultiProtocolStreamScanner,
        OSINTIntegrationScanner,
        CredentialBruteforcingScanner,
        ShodanEnrichment,
    ]

__all__ = ['get_builtin_plugins']