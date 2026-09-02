"""SecureX Fraud Engine API Module"""

from fastapi import APIRouter

from .fingerprint import router as fingerprint_router
from .fraud import router as fraud_router
from .health import router as health_router
from .risk import router as risk_router
from .tampering import router as tampering_router

api_router = APIRouter()

api_router.include_router(health_router, tags=["health"])
api_router.include_router(fraud_router, prefix="/api/v1/fraud", tags=["fraud"])
api_router.include_router(risk_router, prefix="/api/v1/risk", tags=["risk"])
api_router.include_router(fingerprint_router, prefix="/api/v1/fingerprint", tags=["fingerprint"])
api_router.include_router(tampering_router, prefix="/api/v1/tampering", tags=["tampering"])
