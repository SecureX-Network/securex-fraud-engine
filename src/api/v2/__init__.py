"""V2 API router aggregation."""

from fastapi import APIRouter

from .analysis import router as analysis_router
from .blockchain import router as blockchain_router
from .documents import router as documents_router
from .fingerprint import router as fingerprint_router
from .fraud import router as fraud_router
from .risk import router as risk_router
from .tampering import router as tampering_router

v2_router = APIRouter(prefix="/api/v2")

v2_router.include_router(fraud_router, prefix="/fraud", tags=["v2-fraud"])
v2_router.include_router(risk_router, prefix="/risk", tags=["v2-risk"])
v2_router.include_router(tampering_router, prefix="/tampering", tags=["v2-tampering"])
v2_router.include_router(fingerprint_router, prefix="/fingerprint", tags=["v2-fingerprint"])
v2_router.include_router(documents_router, prefix="/documents", tags=["v2-documents"])
v2_router.include_router(blockchain_router, prefix="/blockchain", tags=["v2-blockchain"])
v2_router.include_router(analysis_router, prefix="/analysis", tags=["v2-analysis"])
