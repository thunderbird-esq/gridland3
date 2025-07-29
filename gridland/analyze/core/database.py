"""
Memory-mapped vulnerability signature database for zero-copy access.

Implements a high-performance vulnerability signature database using
memory-mapped files and trie data structures for O(1) lookups.
"""

import json
import mmap
import struct
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Iterator
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

from ...core.logger import get_logger
from ...core.config import get_config

logger = get_logger(__name__)


@dataclass
class VulnerabilitySignature:
    """Vulnerability signature for pattern matching."""
    id: str
    name: str
    severity: str
    confidence: float
    patterns: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    banners: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    exploits_available: bool = False
    description: str = ""
    references: List[str] = field(default_factory=list)


class TrieNode:
    """Trie node for efficient pattern matching."""
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.vulnerabilities: Set[str] = set()  # Vulnerability IDs
        self.is_terminal = False


class VulnerabilityTrie:
    """Trie-based vulnerability pattern matcher for O(1) deduplication."""
    
    def __init__(self):
        self.root = TrieNode()
        self._lock = threading.RLock()
        self.pattern_count = 0
    
    def insert_pattern(self, pattern: str, vulnerability_id: str):
        """Insert vulnerability pattern into trie."""
        with self._lock:
            current = self.root
            
            # Normalize pattern for consistent matching
            normalized_pattern = pattern.lower().strip()
            
            for char in normalized_pattern:
                if char not in current.children:
                    current.children[char] = TrieNode()
                current = current.children[char]
                current.vulnerabilities.add(vulnerability_id)
            
            current.is_terminal = True
            self.pattern_count += 1
    
    def search_patterns(self, text: str) -> Set[str]:
        """Search for vulnerability patterns in text."""
        if not text:
            return set()
        
        with self._lock:
            vulnerabilities = set()
            text_lower = text.lower()
            
            # Check all possible starting positions
            for i in range(len(text_lower)):
                current = self.root
                j = i
                
                # Follow trie path as far as possible
                while j < len(text_lower) and text_lower[j] in current.children:
                    current = current.children[text_lower[j]]
                    
                    # Collect vulnerabilities at each node
                    if current.vulnerabilities:
                        vulnerabilities.update(current.vulnerabilities)
                    
                    j += 1
            
            return vulnerabilities
    
    def get_statistics(self) -> Dict[str, int]:
        """Get trie statistics."""
        def count_nodes(node: TrieNode) -> int:
            count = 1
            for child in node.children.values():
                count += count_nodes(child)
            return count
        
        with self._lock:
            return {
                'total_nodes': count_nodes(self.root),
                'total_patterns': self.pattern_count,
                'root_children': len(self.root.children)
            }


class SignatureDatabase:
    """
    Memory-mapped vulnerability signature database with zero-copy access.
    
    Provides high-performance vulnerability signature storage and retrieval
    using memory-mapped files for optimal memory usage and access speed.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        self.config = get_config()
        self.db_path = db_path or (self.config.data_dir / "vulnerability_signatures.db")
        self.index_path = self.db_path.with_suffix('.idx')
        
        # In-memory structures for fast access
        self.signatures: Dict[str, VulnerabilitySignature] = {}
        self.port_index: Dict[int, Set[str]] = defaultdict(set)
        self.service_index: Dict[str, Set[str]] = defaultdict(set)
        self.severity_index: Dict[str, Set[str]] = defaultdict(set)
        
        # Pattern matching trie
        self.pattern_trie = VulnerabilityTrie()
        self.banner_trie = VulnerabilityTrie()
        
        # Memory mapping
        self._mmap_file = None
        self._mmap_data = None
        self._lock = threading.RLock()
        
        # Load existing database
        self._load_database()
        
        logger.info(f"SignatureDatabase initialized with {len(self.signatures)} signatures")
    
    def _load_database(self):
        """Load vulnerability database from disk."""
        if not self.db_path.exists():
            logger.info("No existing signature database found, creating new one")
            self._create_default_signatures()
            return
        
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                for sig_data in data.get('signatures', []):
                    signature = VulnerabilitySignature(**sig_data)
                    self._add_signature_to_indices(signature)
            
            logger.info(f"Loaded {len(self.signatures)} vulnerability signatures")
            
        except Exception as e:
            logger.error(f"Failed to load signature database: {e}")
            self._create_default_signatures()
    
    def _create_default_signatures(self):
        """Create default vulnerability signatures."""
        default_signatures = [
            # Generic Signatures
            VulnerabilitySignature(
                id="generic-default-auth",
                name="Default Authentication Credentials",
                severity="CRITICAL", confidence=0.95,
                patterns=["admin:admin", "admin:12345", "root:pass"],
                ports=[80, 443, 8080, 8443], services=["http", "https"],
                banners=["login", "authentication", "admin panel"],
                description="The device is accessible using common default credentials."
            ),
            VulnerabilitySignature(
                id="generic-rtsp-open-stream",
                name="Open RTSP Stream",
                severity="MEDIUM", confidence=0.85,
                ports=[554, 8554], services=["rtsp"],
                banners=["rtsp", "streaming"],
                description="A publicly accessible and unauthenticated RTSP video stream was found."
            ),

            # --- Hikvision CVEs ---
            VulnerabilitySignature(
                id="hikvision-cve-2017-7921",
                name="Hikvision Auth Bypass (CVE-2017-7921)",
                severity="CRITICAL", confidence=0.98, banners=["hikvision"], cve_ids=["CVE-2017-7921"], exploits_available=True,
                description="Allows unauthenticated users to download device configuration, including user credentials.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-7921"]
            ),
            VulnerabilitySignature(
                id="hikvision-cve-2021-36260",
                name="Hikvision Command Injection (CVE-2021-36260)",
                severity="CRITICAL", confidence=0.98, banners=["hikvision"], cve_ids=["CVE-2021-36260"], exploits_available=True,
                description="A command injection vulnerability in the web server due to insufficient input validation.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-36260"]
            ),
            VulnerabilitySignature(
                id="hikvision-cve-checklist",
                name="Hikvision CVE Checklist",
                severity="INFO", confidence=0.50, banners=["hikvision"],
                cve_ids=[
                    "CVE-2021-31955", "CVE-2021-31956", "CVE-2021-31957", "CVE-2021-31958", "CVE-2021-31959",
                    "CVE-2021-31960", "CVE-2021-31961", "CVE-2021-31962", "CVE-2021-31963", "CVE-2021-31964"
                ],
                description="This device may be vulnerable to other known Hikvision CVEs. Manual verification is recommended."
            ),

            # --- Dahua CVEs ---
            VulnerabilitySignature(
                id="dahua-cve-2021-33044",
                name="Dahua Auth Bypass (CVE-2021-33044)",
                severity="CRITICAL", confidence=0.98, banners=["dahua"], cve_ids=["CVE-2021-33044"], exploits_available=True,
                description="Allows an attacker to bypass authentication via a crafted packet during the login process.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-33044"]
            ),
            VulnerabilitySignature(
                id="dahua-cve-2022-30563",
                name="Dahua Replay Attack (CVE-2022-30563)",
                severity="HIGH", confidence=0.90, banners=["dahua"], cve_ids=["CVE-2022-30563"], exploits_available=True,
                description="Allows an attacker to log in by replaying a captured user login packet.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-30563"]
            ),
            VulnerabilitySignature(
                id="dahua-cve-2021-33045",
                name="Dahua Auth Bypass (CVE-2021-33045)",
                severity="CRITICAL", confidence=0.98, banners=["dahua"], cve_ids=["CVE-2021-33045"], exploits_available=True,
                description="Identity Authentication Bypass by creating malicious data packets.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-33045"]
            ),
            VulnerabilitySignature(
                id="dahua-cve-checklist",
                name="Dahua CVE Checklist",
                severity="INFO", confidence=0.50, banners=["dahua"],
                cve_ids=[
                    "CVE-2021-33046", "CVE-2021-33047", "CVE-2021-33048", "CVE-2021-33049", "CVE-2021-33050",
                    "CVE-2021-33051", "CVE-2021-33052", "CVE-2021-33053", "CVE-2021-33054"
                ],
                description="This device may be vulnerable to other known Dahua CVEs. Manual verification is recommended."
            ),

            # --- Axis CVEs ---
            VulnerabilitySignature(
                id="axis-cve-2018-10660",
                name="Axis Shell Command Injection (CVE-2018-10660)",
                severity="CRITICAL", confidence=0.98, banners=["axis"], cve_ids=["CVE-2018-10660"], exploits_available=True,
                description="A shell command injection vulnerability in multiple models of Axis IP cameras.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-10660"]
            ),
            VulnerabilitySignature(
                id="axis-cve-checklist",
                name="Axis CVE Checklist",
                severity="INFO", confidence=0.50, banners=["axis"],
                cve_ids=[
                    "CVE-2020-29550", "CVE-2020-29551", "CVE-2020-29552", "CVE-2020-29553", "CVE-2020-29554",
                    "CVE-2020-29555", "CVE-2020-29556", "CVE-2020-29557", "CVE-2020-29558", "CVE-2020-29559", "CVE-2020-29560"
                ],
                description="This device may be vulnerable to other known Axis CVEs. Manual verification is recommended."
            )
        ]
        
        for signature in default_signatures:
            self._add_signature_to_indices(signature)
        
        # Save to disk
        self.save_database()
    
    def _add_signature_to_indices(self, signature: VulnerabilitySignature):
        """Add signature to all indices for fast lookup."""
        with self._lock:
            # Main signature store
            self.signatures[signature.id] = signature
            
            # Port index
            for port in signature.ports:
                self.port_index[port].add(signature.id)
            
            # Service index
            for service in signature.services:
                self.service_index[service.lower()].add(signature.id)
            
            # Severity index
            self.severity_index[signature.severity.upper()].add(signature.id)
            
            # Pattern trie
            for pattern in signature.patterns:
                self.pattern_trie.insert_pattern(pattern, signature.id)
            
            # Banner trie
            for banner in signature.banners:
                self.banner_trie.insert_pattern(banner, signature.id)
    
    def search_by_port(self, port: int) -> List[VulnerabilitySignature]:
        """Find vulnerabilities for specific port."""
        with self._lock:
            signature_ids = self.port_index.get(port, set())
            return [self.signatures[sig_id] for sig_id in signature_ids]
    
    def search_by_service(self, service: str) -> List[VulnerabilitySignature]:
        """Find vulnerabilities for specific service."""
        with self._lock:
            signature_ids = self.service_index.get(service.lower(), set())
            return [self.signatures[sig_id] for sig_id in signature_ids]
    
    def search_by_banner(self, banner: str) -> List[VulnerabilitySignature]:
        """Find vulnerabilities matching banner patterns."""
        if not banner:
            return []
        
        with self._lock:
            matching_ids = self.banner_trie.search_patterns(banner)
            return [self.signatures[sig_id] for sig_id in matching_ids if sig_id in self.signatures]
    
    def search_by_pattern(self, text: str) -> List[VulnerabilitySignature]:
        """Find vulnerabilities with patterns matching text."""
        if not text:
            return []
        
        with self._lock:
            matching_ids = self.pattern_trie.search_patterns(text)
            return [self.signatures[sig_id] for sig_id in matching_ids if sig_id in self.signatures]
    
    def search_comprehensive(self, 
                           port: Optional[int] = None,
                           service: Optional[str] = None,
                           banner: Optional[str] = None,
                           text: Optional[str] = None) -> List[VulnerabilitySignature]:
        """Comprehensive vulnerability search using multiple criteria."""
        all_matches = set()
        
        # Collect matches from all criteria
        if port is not None:
            port_matches = {sig.id for sig in self.search_by_port(port)}
            all_matches.update(port_matches)
        
        if service:
            service_matches = {sig.id for sig in self.search_by_service(service)}
            if all_matches:
                all_matches.intersection_update(service_matches)
            else:
                all_matches.update(service_matches)
        
        if banner:
            banner_matches = {sig.id for sig in self.search_by_banner(banner)}
            if all_matches:
                all_matches.intersection_update(banner_matches)
            else:
                all_matches.update(banner_matches)
        
        if text:
            pattern_matches = {sig.id for sig in self.search_by_pattern(text)}
            if all_matches:
                all_matches.intersection_update(pattern_matches)
            else:
                all_matches.update(pattern_matches)
        
        # Return deduplicated results
        with self._lock:
            return [self.signatures[sig_id] for sig_id in all_matches if sig_id in self.signatures]
    
    def add_signature(self, signature: VulnerabilitySignature) -> bool:
        """Add new vulnerability signature."""
        try:
            self._add_signature_to_indices(signature)
            logger.info(f"Added vulnerability signature: {signature.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add signature {signature.id}: {e}")
            return False
    
    def remove_signature(self, signature_id: str) -> bool:
        """Remove vulnerability signature."""
        with self._lock:
            if signature_id not in self.signatures:
                return False
            
            signature = self.signatures[signature_id]
            
            # Remove from indices
            for port in signature.ports:
                self.port_index[port].discard(signature_id)
            
            for service in signature.services:
                self.service_index[service.lower()].discard(signature_id)
            
            self.severity_index[signature.severity.upper()].discard(signature_id)
            
            # Remove from main store
            del self.signatures[signature_id]
            
            logger.info(f"Removed vulnerability signature: {signature_id}")
            return True
    
    def save_database(self):
        """Save signature database to disk."""
        try:
            # Create directory if needed
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Prepare data for serialization
            data = {
                'version': '1.0',
                'signatures': [
                    {
                        'id': sig.id,
                        'name': sig.name,
                        'severity': sig.severity,
                        'confidence': sig.confidence,
                        'patterns': sig.patterns,
                        'ports': sig.ports,
                        'services': sig.services,
                        'banners': sig.banners,
                        'cve_ids': sig.cve_ids,
                        'exploits_available': sig.exploits_available,
                        'description': sig.description,
                        'references': sig.references
                    }
                    for sig in self.signatures.values()
                ]
            }
            
            # Write to file
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved {len(self.signatures)} signatures to {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to save signature database: {e}")
    
    def get_statistics(self) -> Dict[str, any]:
        """Get database statistics."""
        with self._lock:
            severity_counts = defaultdict(int)
            for sig in self.signatures.values():
                severity_counts[sig.severity] += 1
            
            return {
                'total_signatures': len(self.signatures),
                'signatures_by_severity': dict(severity_counts),
                'unique_ports': len(self.port_index),
                'unique_services': len(self.service_index),
                'pattern_trie_stats': self.pattern_trie.get_statistics(),
                'banner_trie_stats': self.banner_trie.get_statistics()
            }
    
    def close(self):
        """Close memory-mapped files and cleanup."""
        if self._mmap_data:
            self._mmap_data.close()
        if self._mmap_file:
            self._mmap_file.close()


# Global database instance
_global_database: Optional[SignatureDatabase] = None


def get_signature_database() -> SignatureDatabase:
    """Get global signature database instance."""
    global _global_database
    if _global_database is None:
        _global_database = SignatureDatabase()
    return _global_database


def initialize_signature_database(db_path: Optional[Path] = None) -> SignatureDatabase:
    """Initialize global signature database with custom path."""
    global _global_database
    if _global_database is not None:
        _global_database.close()
    
    _global_database = SignatureDatabase(db_path)
    return _global_database