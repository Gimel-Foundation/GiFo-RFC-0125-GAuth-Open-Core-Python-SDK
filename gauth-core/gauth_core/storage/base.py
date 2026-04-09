"""Abstract mandate repository interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class MandateRepository(ABC):

    @abstractmethod
    def create(self, mandate: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def get(self, mandate_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def list_mandates(
        self,
        status: str | None = None,
        agent_id: str | None = None,
        project_id: str | None = None,
        governance_profile: str | None = None,
        cursor: str | None = None,
        limit: int = 20,
    ) -> tuple[list[dict[str, Any]], str | None, int]:
        ...

    @abstractmethod
    def update_status(self, mandate_id: str, new_status: str, **kwargs: Any) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def update_budget(self, mandate_id: str, new_total_cents: int, new_remaining_cents: int) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def update_ttl(self, mandate_id: str, new_ttl_seconds: int, new_expires_at: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def store_audit_record(self, record: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def get_audit_trail(self, mandate_id: str) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def find_active_mandate(self, agent_id: str, project_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def get_children(self, parent_mandate_id: str) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def check_consumption_idempotency(self, enforcement_request_id: str) -> bool:
        ...

    @abstractmethod
    def record_consumption(self, mandate_id: str, enforcement_request_id: str, consumed_cents: int) -> None:
        ...

    @abstractmethod
    def update_reservation(self, mandate_id: str, reserved_cents: int) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def store_delegation(self, parent_id: str, child_id: str, delegation_info: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def get_delegation_chain(self, mandate_id: str) -> list[dict[str, Any]]:
        ...
