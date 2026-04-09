"""In-memory mandate repository for testing and prototyping."""

from __future__ import annotations

import copy
from typing import Any


from gauth_core.storage.base import MandateRepository


class InMemoryMandateRepository(MandateRepository):

    def __init__(self) -> None:
        self._mandates: dict[str, dict[str, Any]] = {}
        self._audit_records: list[dict[str, Any]] = []
        self._consumption_ids: set[str] = set()
        self._delegations: dict[str, dict[str, Any]] = {}

    def create(self, mandate: dict[str, Any]) -> dict[str, Any]:
        mandate_id = mandate["mandate_id"]
        self._mandates[mandate_id] = copy.deepcopy(mandate)
        return copy.deepcopy(mandate)

    def get(self, mandate_id: str) -> dict[str, Any] | None:
        m = self._mandates.get(mandate_id)
        return copy.deepcopy(m) if m else None

    def list_mandates(
        self,
        status: str | None = None,
        agent_id: str | None = None,
        project_id: str | None = None,
        governance_profile: str | None = None,
        cursor: str | None = None,
        limit: int = 20,
    ) -> tuple[list[dict[str, Any]], str | None, int]:
        results = list(self._mandates.values())

        if status:
            results = [m for m in results if m.get("status") == status]
        if agent_id:
            results = [m for m in results if m.get("parties", {}).get("subject") == agent_id]
        if project_id:
            results = [m for m in results if m.get("parties", {}).get("project_id") == project_id]
        if governance_profile:
            results = [m for m in results if m.get("scope", {}).get("governance_profile") == governance_profile]

        results.sort(key=lambda m: m.get("created_at", ""), reverse=True)
        total = len(results)

        start = 0
        if cursor:
            for i, m in enumerate(results):
                if m["mandate_id"] == cursor:
                    start = i + 1
                    break

        page = results[start : start + limit]
        next_cursor = page[-1]["mandate_id"] if len(page) == limit and start + limit < total else None

        return [copy.deepcopy(m) for m in page], next_cursor, total

    def update_status(self, mandate_id: str, new_status: str, **kwargs: Any) -> dict[str, Any] | None:
        m = self._mandates.get(mandate_id)
        if not m:
            return None
        m["status"] = new_status
        for k, v in kwargs.items():
            m[k] = v
        return copy.deepcopy(m)

    def update_budget(self, mandate_id: str, new_total_cents: int, new_remaining_cents: int) -> dict[str, Any] | None:
        m = self._mandates.get(mandate_id)
        if not m:
            return None
        budget = m.setdefault("budget_state", {})
        budget["total_cents"] = new_total_cents
        budget["remaining_cents"] = new_remaining_cents
        budget["consumed_cents"] = new_total_cents - new_remaining_cents
        return copy.deepcopy(m)

    def update_ttl(self, mandate_id: str, new_ttl_seconds: int, new_expires_at: str) -> dict[str, Any] | None:
        m = self._mandates.get(mandate_id)
        if not m:
            return None
        m["ttl_seconds"] = new_ttl_seconds
        m["expires_at"] = new_expires_at
        return copy.deepcopy(m)

    def store_audit_record(self, record: dict[str, Any]) -> None:
        self._audit_records.append(copy.deepcopy(record))

    def get_audit_trail(self, mandate_id: str) -> list[dict[str, Any]]:
        return [
            copy.deepcopy(r)
            for r in self._audit_records
            if r.get("mandate_id") == mandate_id
        ]

    def find_active_mandate(self, agent_id: str, project_id: str) -> dict[str, Any] | None:
        for m in self._mandates.values():
            if (
                m.get("status") == "ACTIVE"
                and m.get("parties", {}).get("subject") == agent_id
                and m.get("parties", {}).get("project_id") == project_id
            ):
                return copy.deepcopy(m)
        return None

    def get_children(self, parent_mandate_id: str) -> list[dict[str, Any]]:
        children = []
        for d in self._delegations.values():
            if d.get("parent_mandate_id") == parent_mandate_id:
                child = self._mandates.get(d.get("child_mandate_id", ""))
                if child:
                    children.append(copy.deepcopy(child))
        return children

    def check_consumption_idempotency(self, enforcement_request_id: str) -> bool:
        return enforcement_request_id in self._consumption_ids

    def record_consumption(self, mandate_id: str, enforcement_request_id: str, consumed_cents: int) -> None:
        self._consumption_ids.add(enforcement_request_id)
        m = self._mandates.get(mandate_id)
        if m:
            budget = m.setdefault("budget_state", {})
            budget["remaining_cents"] = max(0, budget.get("remaining_cents", 0) - consumed_cents)
            budget["consumed_cents"] = budget.get("consumed_cents", 0) + consumed_cents

    def update_reservation(self, mandate_id: str, reserved_cents: int) -> dict[str, Any] | None:
        m = self._mandates.get(mandate_id)
        if not m:
            return None
        budget = m.setdefault("budget_state", {})
        budget["reserved_for_delegations_cents"] = reserved_cents
        return copy.deepcopy(m)

    def store_delegation(self, parent_id: str, child_id: str, delegation_info: dict[str, Any]) -> None:
        key = f"{parent_id}:{child_id}"
        self._delegations[key] = {
            "parent_mandate_id": parent_id,
            "child_mandate_id": child_id,
            **delegation_info,
        }

    def get_delegation_chain(self, mandate_id: str) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        current_id = mandate_id

        visited = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            found_parent = False
            for d in self._delegations.values():
                if d.get("child_mandate_id") == current_id:
                    chain.insert(0, copy.deepcopy(d))
                    current_id = d.get("parent_mandate_id", "")
                    found_parent = True
                    break
            if not found_parent:
                break

        return chain
