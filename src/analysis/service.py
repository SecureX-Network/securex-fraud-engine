"""Unified analysis service for V2.

Orchestrates credential + document + blockchain + tampering + risk + fraud
into a single durable analysis with a stable ``analysis_id``.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from src.blockchain.adapter import build_blockchain_provider
from src.blockchain.verification.provider import BlockchainEvidenceProvider
from src.credential.consistency import compare_credentials
from src.documents.pipeline import DocumentAnalysisService
from src.fraud.models import FraudContext, FraudSignal
from src.fraud.service import FraudDetectionService
from src.persistence.factory import Persistence, create_persistence
from src.persistence.models.records import (
    AnalysisRecord,
    AnalysisSubResult,
    FingerprintRecord,
)
from src.risk.service import RiskAnalysisService, RiskContext

STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"


@dataclass
class AnalysisRequest:
    """Inputs for a unified V2 analysis."""

    credential_id: str | None = None
    credential_type: str | None = None
    issuer_id: str | None = None
    holder_id: str | None = None
    credential_metadata: dict[str, Any] = field(default_factory=dict)
    fingerprints: list[str] = field(default_factory=list)
    verification_history: list[dict[str, Any]] = field(default_factory=list)
    # Document analysis
    document_id: str | None = None
    document_bytes: bytes | None = None
    document_filename: str | None = None
    expected_document_fingerprint: str | None = None
    # Credential consistency metadata (extracted vs supplied)
    supplied_credential_fields: dict[str, Any] = field(default_factory=dict)
    extracted_credential_fields: dict[str, Any] = field(default_factory=dict)
    # Risk context
    entity_type: str = "credential"
    risk_context: dict[str, Any] = field(default_factory=dict)
    risk_signals: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class UnifiedAnalysis:
    """A completed or partially completed unified analysis."""

    analysis_id: str
    status: str
    timestamp: str
    risk: dict[str, Any] | None = None
    fraud: dict[str, Any] | None = None
    tampering: dict[str, Any] | None = None
    fingerprint: dict[str, Any] | None = None
    document: dict[str, Any] | None = None
    blockchain: dict[str, Any] | None = None
    consistency: list[dict[str, Any]] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "status": self.status,
            "timestamp": self.timestamp,
            "risk": self.risk,
            "fraud": self.fraud,
            "tampering": self.tampering,
            "fingerprint": self.fingerprint,
            "document": self.document,
            "blockchain": self.blockchain,
            "consistency": self.consistency,
            "evidence_references": self.evidence_references,
            "recommendations": self.recommendations,
            "errors": self.errors,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnalysisService:
    """Runs the unified analysis pipeline."""

    def __init__(
        self,
        persistence: Persistence | None = None,
        blockchain_provider: BlockchainEvidenceProvider | None = None,
    ):
        self.persistence = persistence or create_persistence()
        self.blockchain = blockchain_provider or build_blockchain_provider()
        self.fraud_service = FraudDetectionService()
        self.risk_service = RiskAnalysisService()
        self.document_service = DocumentAnalysisService()

    def run(self, request: AnalysisRequest) -> UnifiedAnalysis:
        analysis_id = f"an_{uuid4().hex}"
        timestamp = _now()
        errors: list[str] = []

        # ---- Document analysis (optional but primary) --------------------
        document_result = None
        tampering_result = None
        fingerprint_result = None
        if request.document_bytes is not None:
            try:
                doc = self.document_service.analyze(
                    document_id=request.document_id or "document",
                    data=request.document_bytes,
                    filename=request.document_filename,
                    expected_fingerprint=request.expected_document_fingerprint,
                )
                document_result = doc.to_dict()
                fingerprint_result = {
                    "kind": "document",
                    "algorithm": "sha256",
                    "fingerprint": doc.fingerprint,
                }
                tampering_result = document_result["tampering"]
                if fingerprint_result:
                    self.persistence.fingerprints.save(
                        FingerprintRecord(
                            reference_id=analysis_id,
                            kind="document",
                            algorithm="sha256",
                            fingerprint=doc.fingerprint,
                        )
                    )
            except Exception as exc:  # noqa: BLE001 - capture any document failure
                errors.append(str(getattr(exc, "message", "") or exc.__class__.__name__))

        # ---- Credential consistency --------------------------------------
        consistency_signals: list[dict[str, Any]] = []
        if request.supplied_credential_fields:
            consistency_signals = [
                {
                    "signal_type": s.signal_type,
                    "field": s.field,
                    "description": s.description,
                    "severity": s.severity,
                    "deterministic": s.deterministic,
                }
                for s in compare_credentials(
                    request.extracted_credential_fields,
                    request.supplied_credential_fields,
                )
            ]

        # ---- Blockchain evidence -----------------------------------------
        blockchain_evidence = None
        if request.credential_id:
            ev = self.blockchain.verify_credential(
                request.credential_id,
                fingerprint_result["fingerprint"] if fingerprint_result else None,
            )
            blockchain_evidence = ev.to_dict()

        # ---- Fraud (unified) ---------------------------------------------
        document_signals: list[FraudSignal] = []
        for sig in consistency_signals:
            if sig["severity"] in ("high", "critical"):
                document_signals.append(
                    FraudSignal(
                        type=sig["signal_type"],
                        confidence=0.8,
                        description=sig["description"],
                        severity=sig["severity"],
                    )
                )

        tampering_types = [
            s["type"] for s in (tampering_result or {}).get("signals", [])
        ] if tampering_result else []

        fraud_context = FraudContext(
            credential_id=request.credential_id or "unknown",
            credential_type=request.credential_type or "",
            issuer_id=request.issuer_id or "",
            holder_id=request.holder_id,
            metadata=request.credential_metadata,
            fingerprints=request.fingerprints,
            verification_history=request.verification_history,
        )
        fraud_result = self.fraud_service.analyze_unified(
            fraud_context,
            document_signals=document_signals or None,
            blockchain_state=blockchain_evidence["state"] if blockchain_evidence else None,
            tampering_signals=tampering_types or None,
        )

        # ---- Risk ----------------------------------------------------------
        risk_signals = [
            {"risk_level": s.severity}
            for s in fraud_result.signals
        ]
        combined_risk_signals = request.risk_signals + risk_signals
        risk_result = self.risk_service.analyze(
            RiskContext(
                entity_type=request.entity_type,
                entity_id=request.credential_id or request.document_id or "unknown",
                context=request.risk_context,
                signals=combined_risk_signals,
            )
        )

        # ---- Status ---------------------------------------------------------
        if errors:
            status = STATUS_FAILED
        elif document_result is not None or fraud_result.signals:
            status = STATUS_COMPLETED
        else:
            status = STATUS_PARTIAL

        recommendations = list(dict.fromkeys([
            fraud_result.recommendation,
            risk_result.recommendation,
            (document_result or {}).get("tampering", {}).get("recommendation", ""),
        ]))
        recommendations = [r for r in recommendations if r]

        result = UnifiedAnalysis(
            analysis_id=analysis_id,
            status=status,
            timestamp=timestamp,
            risk={
                "risk_score": risk_result.risk_score,
                "risk_level": risk_result.risk_level,
                "severity": risk_result.severity,
                "factors": [
                    {
                        "factor_name": f.factor_name,
                        "weight": f.weight,
                        "value": f.value,
                        "contribution": f.contribution,
                        "description": f.description,
                    }
                    for f in risk_result.factors
                ],
                "evidence": risk_result.evidence,
                "recommendation": risk_result.recommendation,
                "explanation": risk_result.explanation,
            },
            fraud={
                "is_suspicious": fraud_result.is_suspicious,
                "fraud_score": fraud_result.fraud_score,
                "confidence": fraud_result.confidence,
                "severity": fraud_result.severity,
                "signals": [
                    {
                        "type": s.type,
                        "confidence": s.confidence,
                        "severity": s.severity,
                        "description": s.description,
                    }
                    for s in fraud_result.signals
                ],
                "explanation": fraud_result.explanation,
                "recommendation": fraud_result.recommendation,
            },
            tampering=tampering_result,
            fingerprint=fingerprint_result,
            document=document_result,
            blockchain=blockchain_evidence,
            consistency=consistency_signals,
            evidence_references=[analysis_id],
            recommendations=recommendations,
            errors=errors,
        )

        # Persist
        self._persist(
            analysis_id=analysis_id,
            timestamp=timestamp,
            result=result,
            risk_record=risk_result,
            fraud_score=fraud_result.fraud_score,
            risk_score=risk_result.risk_score,
        )
        return result

    def _persist(
        self,
        analysis_id: str,
        timestamp: str,
        result: UnifiedAnalysis,
        risk_record,
        fraud_score: float,
        risk_score: float,
    ) -> None:
        record = AnalysisRecord(
            analysis_id=analysis_id,
            status=result.status,
            timestamp=timestamp,
            risk=result.risk or {},
            fraud=result.fraud or {},
            tampering=result.tampering or {},
            fingerprint=result.fingerprint or {},
            evidence_references=result.evidence_references,
            recommendations=result.recommendations,
        )
        self.persistence.analyses.save_analysis(record)
        if result.tampering is not None:
            self.persistence.tampering.save(
                AnalysisSubResult(analysis_id=analysis_id, result_type="tampering", payload=result.tampering)
            )
        if result.risk is not None:
            self.persistence.risk.save(
                AnalysisSubResult(analysis_id=analysis_id, result_type="risk", payload=result.risk)
            )
        if result.fraud is not None:
            self.persistence.fraud.save(
                AnalysisSubResult(analysis_id=analysis_id, result_type="fraud", payload=result.fraud)
            )
        self.persistence.audit.record(
            event_type="analysis.completed",
            actor=None,
            resource_type="analysis",
            resource_id=analysis_id,
            outcome="success" if result.status != STATUS_FAILED else "failure",
            details={"fraud_score": fraud_score, "risk_score": risk_score},
        )

    def get(self, analysis_id: str) -> UnifiedAnalysis | None:
        record = self.persistence.analyses.get_analysis(analysis_id)
        if record is None:
            return None
        return UnifiedAnalysis(
            analysis_id=record.analysis_id,
            status=record.status,
            timestamp=record.timestamp,
            risk=record.risk,
            fraud=record.fraud,
            tampering=record.tampering,
            fingerprint=record.fingerprint,
            evidence_references=record.evidence_references,
            recommendations=record.recommendations,
        )
