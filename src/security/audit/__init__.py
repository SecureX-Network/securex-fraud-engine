"""Audit boundary.

Audit events for security-relevant actions are recorded through the
persistence ``AuditEventRepository`` (see ``src.persistence``). This module
provides the audit repository interface for a clean security boundary.
"""

from src.persistence.repositories.interfaces import (
    AuditEventRepository,  # noqa: F401
)
