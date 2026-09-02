"""Fraud Rule Engine - Deterministic Rules-Based Analysis

V1 uses explicit rule-based analysis. Machine learning models
can be added later as an augmentation layer.
"""

from .models import FraudContext, FraudSignal


class FraudRuleEngine:
    """Rules-based fraud detection engine.

    V1: Deterministic rules that evaluate credential signals.
    Future: Augment with ML models via a common interface.
    """

    def evaluate(self, context: FraudContext) -> list[FraudSignal]:
        """Evaluate all fraud rules against the context."""
        signals = []
        signals.extend(self._check_metadata_anomalies(context))
        signals.extend(self._check_verification_history(context))
        signals.extend(self._check_fingerprint_consistency(context))
        signals.extend(self._check_lifecycle_anomalies(context))
        return signals

    def _check_metadata_anomalies(self, context: FraudContext) -> list[FraudSignal]:
        """Check for suspicious metadata."""
        signals = []
        metadata = context.metadata or {}

        # Check issuer reputation
        if "issuer_reputation" in metadata:
            reputation = metadata["issuer_reputation"]
            if reputation < 0.3:
                signals.append(
                    FraudSignal(
                        type="low_issuer_reputation",
                        confidence=0.8,
                        description=f"Issuer reputation is low: {reputation}",
                        severity="high",
                        data={"reputation": reputation},
                    )
                )

        # Check for mismatched issuer data
        if "expected_issuer" in metadata and "actual_issuer" in metadata:
            if metadata["expected_issuer"] != metadata["actual_issuer"]:
                signals.append(
                    FraudSignal(
                        type="issuer_mismatch",
                        confidence=0.9,
                        description="Issuer does not match expected value",
                        severity="high",
                        data={
                            "expected": metadata["expected_issuer"],
                            "actual": metadata["actual_issuer"],
                        },
                    )
                )

        return signals

    def _check_verification_history(self, context: FraudContext) -> list[FraudSignal]:
        """Check verification history for anomalies."""
        signals = []
        history = context.verification_history or []

        # Check for excessive verifications
        if len(history) > 100:
            signals.append(
                FraudSignal(
                    type="excessive_verifications",
                    confidence=0.6,
                    description=f"High verification count: {len(history)}",
                    severity="medium",
                    data={"count": len(history)},
                )
            )

        # Check for multiple failures
        failures = sum(1 for v in history if v.get("success") is False)
        if failures > len(history) * 0.5 and len(history) > 10:
            signals.append(
                FraudSignal(
                    type="high_verification_failure",
                    confidence=0.7,
                    description=f"High verification failure rate: {failures}/{len(history)}",
                    severity="medium",
                    data={"failures": failures, "total": len(history)},
                )
            )

        return signals

    def _check_fingerprint_consistency(self, context: FraudContext) -> list[FraudSignal]:
        """Check fingerprint consistency."""
        signals = []
        fingerprints = context.fingerprints or []

        # Check for duplicate fingerprints
        unique = set(fingerprints)
        if len(unique) < len(fingerprints):
            signals.append(
                FraudSignal(
                    type="duplicate_fingerprints",
                    confidence=0.9,
                    description="Duplicate fingerprints detected",
                    severity="critical",
                    data={"count": len(fingerprints) - len(unique)},
                )
            )

        return signals

    def _check_lifecycle_anomalies(self, context: FraudContext) -> list[FraudSignal]:
        """Check credential lifecycle for anomalies."""
        signals = []
        metadata = context.metadata or {}

        # Check for expired credentials being presented as valid
        if "expires_at" in metadata and "current_status" in metadata:
            if metadata["current_status"] == "active":
                # Logic to check if credential actually expired
                pass  # Requires date handling logic

        return signals
