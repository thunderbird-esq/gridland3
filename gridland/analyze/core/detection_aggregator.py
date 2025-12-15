"""
Detection Confidence Aggregator for GRIDLAND v3.0

This module aggregates multiple detection signals from different sources
(banner grabbing, fingerprinting, protocol analysis, etc.) into a unified
confidence score for brand identification.

Key Features:
- Multi-method detection aggregation
- Weighted confidence calculation
- Conflict resolution for disagreeing detections
- Evidence combination and deduplication
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DetectionMethod(Enum):
    """Enumeration of detection methods with associated base weights."""

    BANNER = "banner"  # HTTP/RTSP banner analysis
    HTTP_HEADER = "http_header"  # Server headers, custom headers
    PATTERN_MATCH = "pattern"  # Content pattern matching
    FINGERPRINT = "fingerprint"  # Advanced fingerprinting
    PORT_SERVICE = "port_service"  # Port-to-service correlation
    CERTIFICATE = "certificate"  # SSL/TLS certificate analysis
    BEHAVIORAL = "behavioral"  # Timing and behavioral analysis
    PROTOCOL = "protocol"  # Protocol-specific features


@dataclass
class DetectionResult:
    """Individual detection result from a single method.
    
    Attributes:
        method: The detection method used.
        brand: Detected brand name (lowercase).
        confidence: Confidence score (0.0 to 1.0).
        evidence: Human-readable evidence string.
        source: Source identifier (e.g., plugin name).
        metadata: Optional additional metadata.
    """

    method: DetectionMethod
    brand: str
    confidence: float
    evidence: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and normalize fields."""
        self.brand = self.brand.lower().strip()
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class AggregatedDetection:
    """Aggregated detection result combining multiple methods.
    
    Attributes:
        brand: Final determined brand.
        overall_confidence: Combined confidence score (0.0 to 1.0).
        method_results: List of individual detection results.
        final_verdict: True if confidence meets threshold.
        evidence_summary: Combined evidence from all methods.
        conflict_detected: True if methods disagreed on brand.
        conflict_resolution: Explanation of how conflict was resolved.
    """

    brand: str
    overall_confidence: float
    method_results: list[DetectionResult]
    final_verdict: bool
    evidence_summary: list[str] = field(default_factory=list)
    conflict_detected: bool = False
    conflict_resolution: str = ""


class ConfidenceAggregator:
    """
    Aggregator for multi-method detection confidence scoring.
    
    This class combines detection results from multiple sources to produce
    a single, high-confidence brand identification with conflict resolution.
    
    Attributes:
        method_weights: Weight assigned to each detection method.
        confidence_threshold: Minimum confidence for positive verdict (default: 0.7).
        brand_aliases: Mapping of brand name variations to canonical names.
    """

    def __init__(
        self,
        confidence_threshold: float = 0.7,
        custom_weights: dict[DetectionMethod, float] | None = None,
    ):
        """Initialize the aggregator.
        
        Args:
            confidence_threshold: Minimum confidence for positive verdict.
            custom_weights: Optional custom weights for detection methods.
        """
        self.confidence_threshold = confidence_threshold
        
        # Default weights based on reliability and specificity
        self.method_weights: dict[DetectionMethod, float] = {
            DetectionMethod.FINGERPRINT: 1.0,  # Most reliable
            DetectionMethod.CERTIFICATE: 0.9,  # SSL certs are authoritative
            DetectionMethod.BANNER: 0.8,  # Good but can be spoofed
            DetectionMethod.HTTP_HEADER: 0.7,  # Server headers
            DetectionMethod.BEHAVIORAL: 0.7,  # Timing analysis
            DetectionMethod.PATTERN_MATCH: 0.6,  # Content patterns
            DetectionMethod.PROTOCOL: 0.6,  # Protocol features
            DetectionMethod.PORT_SERVICE: 0.4,  # Least specific
        }
        
        # Apply custom weights if provided
        if custom_weights:
            self.method_weights.update(custom_weights)
        
        # Brand name normalization aliases
        self.brand_aliases: dict[str, str] = {
            "cp plus": "cp_plus",
            "cp-plus": "cp_plus",
            "cpplus": "cp_plus",
            "hik": "hikvision",
            "hikvisiondigital": "hikvision",
            "dh": "dahua",
            "dh-ipc": "dahua",
            "ipc-dahua": "dahua",
            "samsung techwin": "samsung",
            "snb": "samsung",
            "xnb": "samsung",
        }

    def normalize_brand(self, brand: str) -> str:
        """Normalize brand name to canonical form.
        
        Args:
            brand: Raw brand name.
            
        Returns:
            Normalized brand name.
        """
        brand_lower = brand.lower().strip()
        return self.brand_aliases.get(brand_lower, brand_lower)

    def aggregate_detections(
        self, results: list[DetectionResult]
    ) -> AggregatedDetection:
        """
        Aggregate multiple detection results into a single verdict.
        
        Args:
            results: List of DetectionResult objects from various sources.
            
        Returns:
            AggregatedDetection with combined confidence and verdict.
        """
        if not results:
            return AggregatedDetection(
                brand="unknown",
                overall_confidence=0.0,
                method_results=[],
                final_verdict=False,
            )

        # Normalize all brand names
        for result in results:
            result.brand = self.normalize_brand(result.brand)

        # Filter out unknown/empty brands
        valid_results = [r for r in results if r.brand and r.brand != "unknown"]
        
        if not valid_results:
            return AggregatedDetection(
                brand="unknown",
                overall_confidence=0.0,
                method_results=results,
                final_verdict=False,
            )

        # Group by brand
        brand_groups = self._group_by_brand(valid_results)
        
        # Check for conflicts
        conflict_detected = len(brand_groups) > 1
        
        # Resolve conflicts and get winning brand
        if conflict_detected:
            winning_brand, resolution = self._resolve_conflicts(brand_groups)
        else:
            winning_brand = list(brand_groups.keys())[0]
            resolution = ""

        # Calculate weighted confidence for winning brand
        winning_results = brand_groups[winning_brand]
        overall_confidence = self._calculate_weighted_confidence(winning_results)
        
        # Combine evidence
        evidence_summary = self._combine_evidence(winning_results)
        
        # Determine final verdict
        final_verdict = overall_confidence >= self.confidence_threshold

        return AggregatedDetection(
            brand=winning_brand,
            overall_confidence=overall_confidence,
            method_results=results,
            final_verdict=final_verdict,
            evidence_summary=evidence_summary,
            conflict_detected=conflict_detected,
            conflict_resolution=resolution,
        )

    def _group_by_brand(
        self, results: list[DetectionResult]
    ) -> dict[str, list[DetectionResult]]:
        """Group detection results by brand.
        
        Args:
            results: List of detection results.
            
        Returns:
            Dictionary mapping brand names to their detection results.
        """
        groups: dict[str, list[DetectionResult]] = {}
        for result in results:
            if result.brand not in groups:
                groups[result.brand] = []
            groups[result.brand].append(result)
        return groups

    def _calculate_weighted_confidence(
        self, results: list[DetectionResult]
    ) -> float:
        """
        Calculate weighted confidence score using method weights.
        
        Formula: sum(confidence * weight) / sum(weights)
        
        Args:
            results: List of detection results for a single brand.
            
        Returns:
            Weighted confidence score (0.0 to 1.0).
        """
        if not results:
            return 0.0

        total_weighted_confidence = 0.0
        total_weight = 0.0

        for result in results:
            weight = self.method_weights.get(result.method, 0.5)
            total_weighted_confidence += result.confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        # Apply bonus for multiple confirming methods
        method_count = len(set(r.method for r in results))
        multi_method_bonus = min(0.1, (method_count - 1) * 0.03)
        
        base_confidence = total_weighted_confidence / total_weight
        final_confidence = min(1.0, base_confidence + multi_method_bonus)
        
        return round(final_confidence, 4)

    def _resolve_conflicts(
        self, brand_groups: dict[str, list[DetectionResult]]
    ) -> tuple[str, str]:
        """
        Resolve conflicts when multiple brands are detected.
        
        Uses weighted voting based on method weights and confidence scores.
        
        Args:
            brand_groups: Dictionary mapping brands to their detection results.
            
        Returns:
            Tuple of (winning_brand, resolution_explanation).
        """
        brand_scores: dict[str, float] = {}
        
        for brand, results in brand_groups.items():
            # Calculate total weighted score for this brand
            total_score = 0.0
            for result in results:
                weight = self.method_weights.get(result.method, 0.5)
                total_score += result.confidence * weight
            brand_scores[brand] = total_score

        # Find winner
        winning_brand = max(brand_scores.keys(), key=lambda b: brand_scores[b])
        
        # Generate resolution explanation
        sorted_brands = sorted(brand_scores.items(), key=lambda x: x[1], reverse=True)
        resolution = f"Conflict resolved: {winning_brand} (score: {sorted_brands[0][1]:.2f}) "
        resolution += f"vs {', '.join(f'{b}: {s:.2f}' for b, s in sorted_brands[1:])}"
        
        return winning_brand, resolution

    def _combine_evidence(self, results: list[DetectionResult]) -> list[str]:
        """
        Combine and deduplicate evidence from multiple detections.
        
        Args:
            results: List of detection results.
            
        Returns:
            List of unique evidence strings.
        """
        seen: set[str] = set()
        evidence: list[str] = []
        
        for result in results:
            # Create normalized evidence string
            evidence_key = result.evidence.lower().strip()
            if evidence_key not in seen:
                seen.add(evidence_key)
                evidence.append(f"[{result.method.value}] {result.evidence}")
        
        return evidence

    def get_method_weight(self, method: DetectionMethod) -> float:
        """Get the weight for a detection method.
        
        Args:
            method: Detection method.
            
        Returns:
            Weight value (0.0 to 1.0).
        """
        return self.method_weights.get(method, 0.5)

    def set_method_weight(self, method: DetectionMethod, weight: float) -> None:
        """Set custom weight for a detection method.
        
        Args:
            method: Detection method.
            weight: New weight value (0.0 to 1.0).
        """
        self.method_weights[method] = max(0.0, min(1.0, weight))


# Convenience function for quick aggregation
def aggregate_detections(results: list[DetectionResult]) -> AggregatedDetection:
    """Quick aggregation using default settings.
    
    Args:
        results: List of detection results.
        
    Returns:
        Aggregated detection result.
    """
    aggregator = ConfidenceAggregator()
    return aggregator.aggregate_detections(results)
