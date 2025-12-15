"""
Comprehensive Test Suite for Detection Confidence Aggregator.

Tests the detection_aggregator.py module including:
- DetectionMethod enum
- DetectionResult dataclass
- AggregatedDetection dataclass
- ConfidenceAggregator class methods
- Conflict resolution scenarios
- Edge cases
"""

from __future__ import annotations

import pytest

from gridland.analyze.core.detection_aggregator import (
    AggregatedDetection,
    ConfidenceAggregator,
    DetectionMethod,
    DetectionResult,
    aggregate_detections,
)


# =============================================================================
# DetectionMethod Enum Tests
# =============================================================================


class TestDetectionMethod:
    """Tests for DetectionMethod enum."""

    def test_banner_value(self):
        """Test BANNER method value."""
        assert DetectionMethod.BANNER.value == "banner"

    def test_http_header_value(self):
        """Test HTTP_HEADER method value."""
        assert DetectionMethod.HTTP_HEADER.value == "http_header"

    def test_pattern_match_value(self):
        """Test PATTERN_MATCH method value."""
        assert DetectionMethod.PATTERN_MATCH.value == "pattern"

    def test_fingerprint_value(self):
        """Test FINGERPRINT method value."""
        assert DetectionMethod.FINGERPRINT.value == "fingerprint"

    def test_port_service_value(self):
        """Test PORT_SERVICE method value."""
        assert DetectionMethod.PORT_SERVICE.value == "port_service"

    def test_certificate_value(self):
        """Test CERTIFICATE method value."""
        assert DetectionMethod.CERTIFICATE.value == "certificate"

    def test_behavioral_value(self):
        """Test BEHAVIORAL method value."""
        assert DetectionMethod.BEHAVIORAL.value == "behavioral"

    def test_protocol_value(self):
        """Test PROTOCOL method value."""
        assert DetectionMethod.PROTOCOL.value == "protocol"

    def test_enum_count(self):
        """Test all methods are present."""
        assert len(DetectionMethod) == 8


# =============================================================================
# DetectionResult Dataclass Tests
# =============================================================================


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_basic_initialization(self):
        """Test basic initialization."""
        result = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="hikvision",
            confidence=0.85,
            evidence="Found 'Hikvision' in banner",
            source="banner_grabber",
        )
        assert result.brand == "hikvision"
        assert result.confidence == 0.85
        assert result.method == DetectionMethod.BANNER

    def test_brand_normalization_lowercase(self):
        """Test brand names are lowercased."""
        result = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="HIKvision",
            confidence=0.8,
            evidence="Test",
            source="test",
        )
        assert result.brand == "hikvision"

    def test_brand_normalization_whitespace(self):
        """Test brand whitespace is stripped."""
        result = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="  hikvision  ",
            confidence=0.8,
            evidence="Test",
            source="test",
        )
        assert result.brand == "hikvision"

    def test_confidence_capped_at_one(self):
        """Test confidence is capped at 1.0."""
        result = DetectionResult(
            method=DetectionMethod.FINGERPRINT,
            brand="dahua",
            confidence=1.5,
            evidence="Test",
            source="test",
        )
        assert result.confidence == 1.0

    def test_confidence_floored_at_zero(self):
        """Test confidence is floored at 0.0."""
        result = DetectionResult(
            method=DetectionMethod.FINGERPRINT,
            brand="dahua",
            confidence=-0.5,
            evidence="Test",
            source="test",
        )
        assert result.confidence == 0.0

    def test_metadata_default_empty(self):
        """Test metadata defaults to empty dict."""
        result = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="test",
            confidence=0.5,
            evidence="Test",
            source="test",
        )
        assert result.metadata == {}

    def test_metadata_custom_value(self):
        """Test custom metadata is preserved."""
        result = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="test",
            confidence=0.5,
            evidence="Test",
            source="test",
            metadata={"port": 80, "version": "1.0"},
        )
        assert result.metadata["port"] == 80
        assert result.metadata["version"] == "1.0"


# =============================================================================
# AggregatedDetection Dataclass Tests
# =============================================================================


class TestAggregatedDetection:
    """Tests for AggregatedDetection dataclass."""

    def test_basic_initialization(self):
        """Test basic initialization."""
        detection = AggregatedDetection(
            brand="hikvision",
            overall_confidence=0.85,
            method_results=[],
            final_verdict=True,
        )
        assert detection.brand == "hikvision"
        assert detection.overall_confidence == 0.85
        assert detection.final_verdict is True

    def test_defaults(self):
        """Test default values."""
        detection = AggregatedDetection(
            brand="test",
            overall_confidence=0.5,
            method_results=[],
            final_verdict=False,
        )
        assert detection.evidence_summary == []
        assert detection.conflict_detected is False
        assert detection.conflict_resolution == ""


# =============================================================================
# ConfidenceAggregator Initialization Tests
# =============================================================================


class TestConfidenceAggregatorInit:
    """Tests for ConfidenceAggregator initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        aggregator = ConfidenceAggregator()
        assert aggregator.confidence_threshold == 0.7
        assert len(aggregator.method_weights) == 8

    def test_custom_threshold(self):
        """Test custom confidence threshold."""
        aggregator = ConfidenceAggregator(confidence_threshold=0.9)
        assert aggregator.confidence_threshold == 0.9

    def test_custom_weights(self):
        """Test custom method weights."""
        custom = {DetectionMethod.BANNER: 0.95}
        aggregator = ConfidenceAggregator(custom_weights=custom)
        assert aggregator.method_weights[DetectionMethod.BANNER] == 0.95

    def test_fingerprint_highest_weight(self):
        """Test fingerprint has highest default weight."""
        aggregator = ConfidenceAggregator()
        fingerprint_weight = aggregator.method_weights[DetectionMethod.FINGERPRINT]
        for method, weight in aggregator.method_weights.items():
            if method != DetectionMethod.FINGERPRINT:
                assert fingerprint_weight >= weight

    def test_port_service_lowest_weight(self):
        """Test port_service has lowest default weight."""
        aggregator = ConfidenceAggregator()
        port_weight = aggregator.method_weights[DetectionMethod.PORT_SERVICE]
        for method, weight in aggregator.method_weights.items():
            if method != DetectionMethod.PORT_SERVICE:
                assert port_weight <= weight

    def test_brand_aliases_initialized(self):
        """Test brand aliases are initialized."""
        aggregator = ConfidenceAggregator()
        assert len(aggregator.brand_aliases) > 0
        assert "cp plus" in aggregator.brand_aliases


# =============================================================================
# Brand Normalization Tests
# =============================================================================


class TestBrandNormalization:
    """Tests for brand name normalization."""

    @pytest.fixture
    def aggregator(self):
        return ConfidenceAggregator()

    def test_normalize_cp_plus_variants(self, aggregator):
        """Test CP Plus name variants are normalized."""
        variants = ["cp plus", "cp-plus", "cpplus"]
        for variant in variants:
            assert aggregator.normalize_brand(variant) == "cp_plus"

    def test_normalize_hikvision_variants(self, aggregator):
        """Test Hikvision name variants are normalized."""
        assert aggregator.normalize_brand("hik") == "hikvision"

    def test_normalize_dahua_variants(self, aggregator):
        """Test Dahua name variants are normalized."""
        variants = ["dh", "dh-ipc"]
        for variant in variants:
            assert aggregator.normalize_brand(variant) == "dahua"

    def test_normalize_unknown_brand(self, aggregator):
        """Test unknown brands are returned as-is (lowercased)."""
        assert aggregator.normalize_brand("UnknownBrand") == "unknownbrand"

    def test_normalize_with_whitespace(self, aggregator):
        """Test normalization handles whitespace."""
        assert aggregator.normalize_brand("  HIKVISION  ") == "hikvision"


# =============================================================================
# Aggregation Tests - Basic
# =============================================================================


class TestAggregationBasic:
    """Tests for basic aggregation functionality."""

    @pytest.fixture
    def aggregator(self):
        return ConfidenceAggregator()

    def test_empty_results(self, aggregator):
        """Test aggregation with empty results."""
        result = aggregator.aggregate_detections([])
        assert result.brand == "unknown"
        assert result.overall_confidence == 0.0
        assert result.final_verdict is False

    def test_single_result(self, aggregator):
        """Test aggregation with single result."""
        detection = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="hikvision",
            confidence=0.8,
            evidence="Found Hikvision in banner",
            source="test",
        )
        result = aggregator.aggregate_detections([detection])
        assert result.brand == "hikvision"
        assert result.overall_confidence > 0
        assert result.conflict_detected is False

    def test_multiple_same_brand(self, aggregator):
        """Test aggregation with multiple same-brand results."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.7,
                evidence="Banner evidence",
                source="banner",
            ),
            DetectionResult(
                method=DetectionMethod.FINGERPRINT,
                brand="hikvision",
                confidence=0.9,
                evidence="Fingerprint evidence",
                source="fingerprint",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert result.brand == "hikvision"
        assert not result.conflict_detected
        # Confidence should be higher due to multiple methods
        assert result.overall_confidence > 0.7

    def test_all_unknown_brands(self, aggregator):
        """Test aggregation when all brands are unknown."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="unknown",
                confidence=0.5,
                evidence="No brand found",
                source="test",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert result.brand == "unknown"
        assert result.final_verdict is False


# =============================================================================
# Weighted Confidence Calculation Tests
# =============================================================================


class TestWeightedConfidence:
    """Tests for weighted confidence calculation."""

    @pytest.fixture
    def aggregator(self):
        return ConfidenceAggregator()

    def test_fingerprint_weight_higher(self, aggregator):
        """Test fingerprint method has higher weight in conflict resolution."""
        # With single results, weight normalizes out, so test via conflict
        # The weight matters when resolving conflicts between methods
        fingerprint_result = DetectionResult(
            method=DetectionMethod.FINGERPRINT,
            brand="hikvision",
            confidence=0.7,  # Lower confidence
            evidence="Fingerprint",
            source="test",
        )
        port_result = DetectionResult(
            method=DetectionMethod.PORT_SERVICE,
            brand="dahua",
            confidence=0.7,  # Same confidence
            evidence="Port",
            source="test",
        )
        
        # Fingerprint should win due to higher weight (1.0 vs 0.4)
        agg = aggregator.aggregate_detections([fingerprint_result, port_result])
        assert agg.brand == "hikvision"  # Fingerprint wins

    def test_multi_method_bonus(self, aggregator):
        """Test bonus for multiple confirming methods."""
        single = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="hikvision",
            confidence=0.8,
            evidence="Banner",
            source="test",
        )
        
        multiple = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.8,
                evidence="Banner",
                source="test",
            ),
            DetectionResult(
                method=DetectionMethod.FINGERPRINT,
                brand="hikvision",
                confidence=0.8,
                evidence="Fingerprint",
                source="test",
            ),
        ]
        
        single_result = aggregator.aggregate_detections([single])
        multi_result = aggregator.aggregate_detections(multiple)
        
        # Multiple methods should have bonus
        assert multi_result.overall_confidence > single_result.overall_confidence


# =============================================================================
# Conflict Resolution Tests
# =============================================================================


class TestConflictResolution:
    """Tests for conflict resolution."""

    @pytest.fixture
    def aggregator(self):
        return ConfidenceAggregator()

    def test_conflict_detected(self, aggregator):
        """Test conflict is detected when brands disagree."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.7,
                evidence="Banner says Hikvision",
                source="banner",
            ),
            DetectionResult(
                method=DetectionMethod.FINGERPRINT,
                brand="dahua",
                confidence=0.6,
                evidence="Fingerprint says Dahua",
                source="fingerprint",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert result.conflict_detected is True
        assert result.conflict_resolution != ""

    def test_higher_weight_wins(self, aggregator):
        """Test higher weighted method wins conflict."""
        detections = [
            DetectionResult(
                method=DetectionMethod.PORT_SERVICE,  # Low weight
                brand="hikvision",
                confidence=0.9,
                evidence="Port suggests Hikvision",
                source="port",
            ),
            DetectionResult(
                method=DetectionMethod.FINGERPRINT,  # High weight
                brand="dahua",
                confidence=0.8,
                evidence="Fingerprint says Dahua",
                source="fingerprint",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        # Fingerprint should win due to higher weight
        assert result.brand == "dahua"

    def test_higher_confidence_can_win(self, aggregator):
        """Test higher confidence can overcome lower weight."""
        detections = [
            DetectionResult(
                method=DetectionMethod.PATTERN_MATCH,
                brand="hikvision",
                confidence=0.95,
                evidence="Strong pattern match",
                source="pattern",
            ),
            DetectionResult(
                method=DetectionMethod.PORT_SERVICE,
                brand="dahua",
                confidence=0.3,
                evidence="Weak port correlation",
                source="port",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        # Pattern match should win (0.95 * 0.6 = 0.57 > 0.3 * 0.4 = 0.12)
        assert result.brand == "hikvision"

    def test_conflict_resolution_explanation(self, aggregator):
        """Test conflict resolution has explanation."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="axis",
                confidence=0.6,
                evidence="Banner",
                source="test",
            ),
            DetectionResult(
                method=DetectionMethod.FINGERPRINT,
                brand="hikvision",
                confidence=0.8,
                evidence="Fingerprint",
                source="test",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert "Conflict resolved" in result.conflict_resolution
        assert "hikvision" in result.conflict_resolution


# =============================================================================
# Evidence Combination Tests
# =============================================================================


class TestEvidenceCombination:
    """Tests for evidence combination."""

    @pytest.fixture
    def aggregator(self):
        return ConfidenceAggregator()

    def test_evidence_combined(self, aggregator):
        """Test evidence from multiple sources is combined."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.8,
                evidence="Found in HTTP banner",
                source="banner",
            ),
            DetectionResult(
                method=DetectionMethod.FINGERPRINT,
                brand="hikvision",
                confidence=0.9,
                evidence="Behavioral pattern match",
                source="fingerprint",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert len(result.evidence_summary) == 2

    def test_evidence_deduplicated(self, aggregator):
        """Test duplicate evidence is deduplicated."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.8,
                evidence="Found Hikvision",
                source="banner1",
            ),
            DetectionResult(
                method=DetectionMethod.HTTP_HEADER,
                brand="hikvision",
                confidence=0.7,
                evidence="Found Hikvision",  # Duplicate
                source="banner2",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        # Should deduplicate
        assert len(result.evidence_summary) == 1

    def test_evidence_includes_method_tag(self, aggregator):
        """Test evidence includes method identifier."""
        detections = [
            DetectionResult(
                method=DetectionMethod.CERTIFICATE,
                brand="axis",
                confidence=0.9,
                evidence="SSL cert subject",
                source="ssl",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert "[certificate]" in result.evidence_summary[0]


# =============================================================================
# Final Verdict Tests
# =============================================================================


class TestFinalVerdict:
    """Tests for final verdict determination."""

    def test_verdict_above_threshold(self):
        """Test positive verdict above threshold."""
        aggregator = ConfidenceAggregator(confidence_threshold=0.7)
        detection = DetectionResult(
            method=DetectionMethod.FINGERPRINT,
            brand="hikvision",
            confidence=0.9,
            evidence="High confidence",
            source="test",
        )
        result = aggregator.aggregate_detections([detection])
        assert result.final_verdict is True

    def test_verdict_below_threshold(self):
        """Test negative verdict below threshold."""
        aggregator = ConfidenceAggregator(confidence_threshold=0.9)
        detection = DetectionResult(
            method=DetectionMethod.PORT_SERVICE,
            brand="hikvision",
            confidence=0.5,
            evidence="Low confidence",
            source="test",
        )
        result = aggregator.aggregate_detections([detection])
        assert result.final_verdict is False

    def test_verdict_at_threshold(self):
        """Test verdict at exactly threshold."""
        aggregator = ConfidenceAggregator(confidence_threshold=0.7)
        # Create detection that results in exactly 0.7 confidence
        detection = DetectionResult(
            method=DetectionMethod.FINGERPRINT,  # weight 1.0
            brand="test",
            confidence=0.7,
            evidence="Test",
            source="test",
        )
        result = aggregator.aggregate_detections([detection])
        assert result.final_verdict is True


# =============================================================================
# Method Weight Manipulation Tests
# =============================================================================


class TestMethodWeights:
    """Tests for method weight manipulation."""

    def test_get_method_weight(self):
        """Test getting method weight."""
        aggregator = ConfidenceAggregator()
        weight = aggregator.get_method_weight(DetectionMethod.FINGERPRINT)
        assert weight == 1.0

    def test_set_method_weight(self):
        """Test setting method weight."""
        aggregator = ConfidenceAggregator()
        aggregator.set_method_weight(DetectionMethod.BANNER, 0.5)
        assert aggregator.method_weights[DetectionMethod.BANNER] == 0.5

    def test_set_method_weight_capped(self):
        """Test weight is capped at 1.0."""
        aggregator = ConfidenceAggregator()
        aggregator.set_method_weight(DetectionMethod.BANNER, 1.5)
        assert aggregator.method_weights[DetectionMethod.BANNER] == 1.0

    def test_set_method_weight_floored(self):
        """Test weight is floored at 0.0."""
        aggregator = ConfidenceAggregator()
        aggregator.set_method_weight(DetectionMethod.BANNER, -0.5)
        assert aggregator.method_weights[DetectionMethod.BANNER] == 0.0


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunction:
    """Tests for the aggregate_detections convenience function."""

    def test_aggregate_detections_function(self):
        """Test the standalone aggregate_detections function."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.8,
                evidence="Test",
                source="test",
            ),
        ]
        result = aggregate_detections(detections)
        assert isinstance(result, AggregatedDetection)
        assert result.brand == "hikvision"


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def aggregator(self):
        return ConfidenceAggregator()

    def test_empty_brand_string(self, aggregator):
        """Test handling of empty brand string."""
        detection = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="",
            confidence=0.8,
            evidence="No brand found",
            source="test",
        )
        result = aggregator.aggregate_detections([detection])
        assert result.brand == "unknown"

    def test_whitespace_brand(self, aggregator):
        """Test handling of whitespace-only brand."""
        detection = DetectionResult(
            method=DetectionMethod.BANNER,
            brand="   ",
            confidence=0.8,
            evidence="No brand found",
            source="test",
        )
        result = aggregator.aggregate_detections([detection])
        assert result.brand == "unknown"

    def test_many_methods_same_brand(self, aggregator):
        """Test aggregation with many methods agreeing."""
        detections = [
            DetectionResult(
                method=method,
                brand="hikvision",
                confidence=0.7,
                evidence=f"Evidence from {method.value}",
                source="test",
            )
            for method in DetectionMethod
        ]
        result = aggregator.aggregate_detections(detections)
        assert result.brand == "hikvision"
        assert result.overall_confidence > 0.7  # Should have multi-method bonus

    def test_zero_confidence_results(self, aggregator):
        """Test handling of zero confidence results."""
        detections = [
            DetectionResult(
                method=DetectionMethod.BANNER,
                brand="hikvision",
                confidence=0.0,
                evidence="Zero confidence",
                source="test",
            ),
        ]
        result = aggregator.aggregate_detections(detections)
        assert result.overall_confidence == 0.0
