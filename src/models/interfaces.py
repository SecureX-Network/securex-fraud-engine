"""ML model interfaces (PLANNED).

No production ML model is implemented. These interfaces define where a real
trained model can later be plugged in without changing the rest of the engine.
Until a trained and evaluated model exists, ``has_model`` returns False and the
engine remains fully deterministic.
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class FraudModel(Protocol):
    """Interface for a future ML fraud model."""

    def predict(self, features: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class RiskModel(Protocol):
    """Interface for a future ML risk model."""

    def predict(self, features: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class TamperingModel(Protocol):
    """Interface for a future ML tampering model."""

    def predict(self, features: dict[str, Any]) -> dict[str, Any]: ...
