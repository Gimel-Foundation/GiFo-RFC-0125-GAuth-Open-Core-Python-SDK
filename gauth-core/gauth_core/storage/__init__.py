"""GAuth storage abstraction — mandate repository interfaces."""

from gauth_core.storage.base import MandateRepository
from gauth_core.storage.memory import InMemoryMandateRepository

__all__ = [
    "MandateRepository",
    "InMemoryMandateRepository",
]

try:
    from gauth_core.storage.sqlalchemy import SQLAlchemyMandateRepository
    __all__.append("SQLAlchemyMandateRepository")
except ImportError:
    pass
