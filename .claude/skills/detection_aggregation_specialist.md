# Detection Confidence Aggregation Specialist Skill

## Skill Purpose

Expert in multi-method detection correlation and confidence scoring systems. Specializes in weighted voting algorithms, conflict resolution, evidence aggregation, and statistical confidence calculation.

## Core Competencies

### 1. Confidence Scoring Algorithms

- Weighted averaging with normalization
- Bayesian probability updating
- Multi-source evidence aggregation
- Confidence interval calculation
- Threshold-based decision making

### 2. Conflict Resolution

- Weighted voting mechanisms
- Evidence strength comparison
- Tie-breaking strategies
- Fallback hierarchies
- Uncertainty quantification

### 3. Detection Method Integration

- Banner analysis integration
- HTTP header extraction
- Fingerprint module integration
- Port-service correlation
- SSL certificate analysis

### 4. Statistical Validation

- Accuracy measurement
- False positive rate calculation
- Precision and recall metrics
- Confusion matrix analysis
- ROC curve evaluation

## Implementation Guidelines

### File Structure

```
gridland/analyze/core/detection_aggregator.py
├── DetectionMethod (Enum)
├── DetectionResult (dataclass)
├── AggregatedDetection (dataclass)
└── ConfidenceAggregator (class)
    ├── __init__()
    ├── aggregate_detections()
    ├── _calculate_weighted_confidence()
    ├── _resolve_conflicts()
    ├── _aggregate_evidence()
    └── _generate_verdict()
```

### DetectionMethod Enum

```python
from enum import Enum, auto

class DetectionMethod(Enum):
    """Detection methods with implicit priority order."""
    FINGERPRINT = auto()      # Highest confidence
    BANNER = auto()
    HTTP_HEADER = auto()
    PATTERN_MATCH = auto()
    PORT_SERVICE = auto()
    CERTIFICATE = auto()      # Lowest confidence
```

### DetectionResult Dataclass

```python
@dataclass
class DetectionResult:
    """Single detection method result."""
    method: DetectionMethod
    brand: str
    confidence: float  # 0.0-1.0
    evidence: str
    source: str  # Which plugin/module generated this
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Validate confidence range."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")
```

### AggregatedDetection Dataclass

```python
@dataclass
class AggregatedDetection:
    """Aggregated detection result from multiple methods."""
    brand: str
    overall_confidence: float  # 0.0-1.0
    method_results: List[DetectionResult]
    final_verdict: bool  # True if confidence >= threshold
    conflicting_detections: List[str]  # Other brands detected
    evidence_summary: str
    timestamp: datetime = field(default_factory=datetime.now)
```

### Weight Configuration

```python
METHOD_WEIGHTS = {
    DetectionMethod.FINGERPRINT: 0.9,      # Highest trust
    DetectionMethod.BANNER: 0.7,
    DetectionMethod.HTTP_HEADER: 0.6,
    DetectionMethod.PATTERN_MATCH: 0.5,
    DetectionMethod.PORT_SERVICE: 0.4,
    DetectionMethod.CERTIFICATE: 0.3       # Lowest trust
}

CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence for positive verdict
```

## Algorithm Specifications

### Weighted Confidence Calculation

```
Formula:
  overall_confidence = Σ(method_confidence_i × method_weight_i) / Σ(method_weight_i)

Where:
  - method_confidence_i = confidence reported by detection method i
  - method_weight_i = weight for detection method i
  - Σ = sum over all detection methods that detected the same brand
```

### Conflict Resolution Algorithm

```
1. Group detections by brand
2. For each brand:
   - Calculate weighted confidence using formula above
   - Track which methods contributed
3. Select brand with highest weighted confidence
4. If multiple brands within 0.1 of each other:
   - Count number of detection methods
   - Use method count as tie-breaker
5. Return winning brand + conflicting brands list
```

### Evidence Aggregation

```
Combine evidence strings from all methods:
"Brand detected via: FINGERPRINT (conf=0.95, 'Model: DS-2CD2032'),
                     BANNER (conf=0.85, 'Hikvision-Webs'),
                     HTTP_HEADER (conf=0.75, 'Server: Hikvision')"
```

## Testing Requirements

```
tests/analyze/core/test_detection_aggregator.py
├── TestDetectionMethod (2 tests)
├── TestDetectionResult (5 tests)
├── TestAggregatedDetection (3 tests)
├── TestWeightedConfidence (10 tests)
├── TestConflictResolution (12 tests)
├── TestEvidenceAggregation (4 tests)
└── TestIntegration (4 tests)
```

### Test Scenarios

**Scenario 1: Single Brand, Multiple Methods**

```python
detections = [
    DetectionResult(DetectionMethod.FINGERPRINT, "Hikvision", 0.95, "Model: DS-2CD2032", "fingerprinter"),
    DetectionResult(DetectionMethod.BANNER, "Hikvision", 0.85, "Hikvision-Webs", "banner_grabber"),
    DetectionResult(DetectionMethod.HTTP_HEADER, "Hikvision", 0.75, "Server: Hikvision", "banner_grabber"),
]

# Expected:
# overall_confidence = (0.95×0.9 + 0.85×0.7 + 0.75×0.6) / (0.9 + 0.7 + 0.6)
#                    = (0.855 + 0.595 + 0.45) / 2.2
#                    = 1.9 / 2.2 = 0.864
# verdict = True (>= 0.7 threshold)
```

**Scenario 2: Conflicting Brands**

```python
detections = [
    DetectionResult(DetectionMethod.BANNER, "Hikvision", 0.7, "Hikvision", "banner"),
    DetectionResult(DetectionMethod.FINGERPRINT, "Dahua", 0.9, "Model: IPC-HDBW", "fingerprinter"),
]

# Expected:
# Hikvision: 0.7 × 0.7 / 0.7 = 0.7
# Dahua: 0.9 × 0.9 / 0.9 = 0.9
# Winner: Dahua (higher confidence)
# conflicting_detections = ["Hikvision"]
```

**Scenario 3: Tie-Breaking by Method Count**

```python
detections = [
    DetectionResult(DetectionMethod.PATTERN_MATCH, "Hikvision", 0.6, "Pattern", "scanner"),
    DetectionResult(DetectionMethod.PORT_SERVICE, "Hikvision", 0.5, "Port 8000", "network"),
    DetectionResult(DetectionMethod.FINGERPRINT, "Dahua", 0.8, "Model", "fingerprinter"),
]

# Expected:
# Hikvision: (0.6×0.5 + 0.5×0.4) / (0.5 + 0.4) = 0.56
# Dahua: (0.8×0.9) / 0.9 = 0.8
# Winner: Dahua (higher confidence)
```

## Integration Points

### Analysis Engine Integration

```python
# In analysis_engine.py

from gridland.analyze.core.detection_aggregator import ConfidenceAggregator, DetectionResult, DetectionMethod

class AnalysisEngine:
    def __init__(self):
        self.aggregator = ConfidenceAggregator()

    async def analyze_target(self, ip: str, port: int):
        # Collect detections from various sources
        detections = []

        # From banner
        if banner:
            detections.append(DetectionResult(
                DetectionMethod.BANNER,
                brand=self._extract_brand_from_banner(banner),
                confidence=0.85,
                evidence=f"Banner: {banner}",
                source="banner_grabber"
            ))

        # From fingerprinting
        fingerprint = await self.fingerprinter.fingerprint(ip, port)
        if fingerprint.success:
            detections.append(DetectionResult(
                DetectionMethod.FINGERPRINT,
                brand=fingerprint.fingerprint.brand,
                confidence=fingerprint.fingerprint.confidence_score,
                evidence=f"Model: {fingerprint.fingerprint.model}",
                source="fingerprinting_module"
            ))

        # Aggregate
        aggregated = self.aggregator.aggregate_detections(detections)

        # Use aggregated brand for targeted scanning
        if aggregated.final_verdict:
            brand = aggregated.brand
            # Run brand-specific scanners
```

## Performance Benchmarks

- ✅ Aggregation time: <10ms for 10 detection results
- ✅ Memory usage: <1MB per aggregation
- ✅ Accuracy: 95%+ on validation set
- ✅ False positive reduction: 30%+ vs single-method

## Success Criteria

### Functionality

- [ ] Aggregates 6+ detection methods
- [ ] Weighted confidence calculation accurate to 0.01
- [ ] Conflict resolution deterministic
- [ ] Evidence aggregation comprehensive

### Testing

- [ ] 40+ unit tests passing
- [ ] Edge cases covered (0 detections, all conflicts, etc.)
- [ ] Statistical validation on test dataset
- [ ] Performance benchmarks met

### Integration

- [ ] Analysis engine uses aggregator
- [ ] Detection results flow from plugins
- [ ] Brand-specific scanners use aggregated brand
- [ ] No circular dependencies

### Documentation

- [ ] Algorithm documented with examples
- [ ] Weight tuning guide provided
- [ ] Integration guide complete
- [ ] Performance characteristics documented

## Common Pitfalls to Avoid

❌ **DO NOT**:

- Divide by zero (check weight sum > 0)
- Assume detections list is non-empty
- Ignore confidence out of range
- Skip normalization step
- Hardcode thresholds without config
- Return None on edge cases

✅ **DO**:

- Validate all inputs
- Handle empty detections list (return default)
- Clamp confidences to [0.0, 1.0]
- Normalize weights properly
- Load thresholds from config
- Return AggregatedDetection always (with appropriate values)

## Advanced Features (Optional)

### Bayesian Update Formula

```python
def bayesian_update(prior: float, likelihood: float, evidence_strength: float) -> float:
    """
    Update confidence using Bayesian inference.

    Args:
        prior: Prior probability (previous confidence)
        likelihood: Likelihood of evidence given hypothesis
        evidence_strength: Strength of new evidence (0.0-1.0)

    Returns:
        Updated posterior probability
    """
    posterior = (likelihood * prior * evidence_strength) / (
        (likelihood * prior * evidence_strength) +
        ((1 - likelihood) * (1 - prior) * evidence_strength)
    )
    return posterior
```

### Temporal Decay

```python
def apply_temporal_decay(confidence: float, age_seconds: int, half_life: int = 3600) -> float:
    """
    Reduce confidence based on age of detection.

    Args:
        confidence: Original confidence
        age_seconds: Time since detection
        half_life: Seconds for confidence to decay to 50%

    Returns:
        Decayed confidence
    """
    decay_factor = 0.5 ** (age_seconds / half_life)
    return confidence * decay_factor
```

## Ready for Deployment

- Agent can work independently
- Algorithms mathematically specified
- Test scenarios comprehensive
- Integration requirements clear
