"""SQLAlchemy-based mandate repository for production use.

Install with: pip install gauth-core[sql]

This module provides a PostgreSQL-backed implementation of MandateRepository
using SQLAlchemy ORM. It requires SQLAlchemy 2.0+ and a PostgreSQL database.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

try:
    from sqlalchemy import (
        Column,
        DateTime,
        Integer,
        String,
        Text,
        JSON,
        Boolean,
        create_engine,
        select,
        func,
    )
    from sqlalchemy.orm import (
        DeclarativeBase,
        Session,
        sessionmaker,
    )

    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

from gauth_core.storage.base import MandateRepository


def _require_sqlalchemy() -> None:
    if not HAS_SQLALCHEMY:
        raise ImportError(
            "SQLAlchemy is required for the SQL storage backend. "
            "Install with: pip install gauth-core[sql]"
        )


if HAS_SQLALCHEMY:

    class Base(DeclarativeBase):
        pass

    class MandateRow(Base):
        __tablename__ = "gauth_mandates"

        mandate_id = Column(String(64), primary_key=True)
        status = Column(String(32), nullable=False, index=True)
        parties = Column(JSON, nullable=False)
        scope = Column(JSON, nullable=False)
        requirements = Column(JSON, nullable=False)
        scope_checksum = Column(String(128))
        tool_permissions_hash = Column(String(128))
        platform_permissions_hash = Column(String(128))
        budget_state = Column(JSON)
        parent_mandate_id = Column(String(64), index=True)
        created_at = Column(String(64))
        activated_at = Column(String(64))
        expires_at = Column(String(64))
        ttl_seconds = Column(Integer)
        data = Column(JSON)

    class AuditRow(Base):
        __tablename__ = "gauth_audit"

        id = Column(Integer, primary_key=True, autoincrement=True)
        mandate_id = Column(String(64), index=True, nullable=False)
        operation = Column(String(32), nullable=False)
        performed_by = Column(String(256))
        timestamp = Column(String(64))
        data = Column(JSON)

    class ConsumptionRow(Base):
        __tablename__ = "gauth_consumptions"

        enforcement_request_id = Column(String(128), primary_key=True)
        mandate_id = Column(String(64), index=True, nullable=False)
        consumed_cents = Column(Integer, nullable=False)
        recorded_at = Column(String(64))

    class DelegationRow(Base):
        __tablename__ = "gauth_delegations"

        id = Column(Integer, primary_key=True, autoincrement=True)
        parent_mandate_id = Column(String(64), index=True, nullable=False)
        child_mandate_id = Column(String(64), index=True, nullable=False)
        data = Column(JSON)


class SQLAlchemyMandateRepository(MandateRepository):

    def __init__(self, database_url: str, echo: bool = False) -> None:
        _require_sqlalchemy()
        self._engine = create_engine(database_url, echo=echo)
        Base.metadata.create_all(self._engine)
        self._session_factory = sessionmaker(bind=self._engine)

    def _session(self) -> Session:
        return self._session_factory()

    def _mandate_to_dict(self, row: MandateRow) -> dict[str, Any]:
        result = {
            "mandate_id": row.mandate_id,
            "status": row.status,
            "parties": row.parties or {},
            "scope": row.scope or {},
            "requirements": row.requirements or {},
            "scope_checksum": row.scope_checksum,
            "tool_permissions_hash": row.tool_permissions_hash,
            "platform_permissions_hash": row.platform_permissions_hash,
            "budget_state": row.budget_state or {},
            "parent_mandate_id": row.parent_mandate_id,
            "created_at": row.created_at,
            "activated_at": row.activated_at,
            "expires_at": row.expires_at,
            "ttl_seconds": row.ttl_seconds,
        }
        if row.data:
            result.update(row.data)
        return result

    def create(self, mandate: dict[str, Any]) -> dict[str, Any]:
        with self._session() as session:
            row = MandateRow(
                mandate_id=mandate["mandate_id"],
                status=mandate.get("status", "DRAFT"),
                parties=mandate.get("parties"),
                scope=mandate.get("scope"),
                requirements=mandate.get("requirements"),
                scope_checksum=mandate.get("scope_checksum"),
                tool_permissions_hash=mandate.get("tool_permissions_hash"),
                platform_permissions_hash=mandate.get("platform_permissions_hash"),
                budget_state=mandate.get("budget_state"),
                parent_mandate_id=mandate.get("parent_mandate_id"),
                created_at=mandate.get("created_at"),
                activated_at=mandate.get("activated_at"),
                expires_at=mandate.get("expires_at"),
                ttl_seconds=mandate.get("ttl_seconds"),
                data={k: v for k, v in mandate.items()
                      if k not in {"mandate_id", "status", "parties", "scope",
                                   "requirements", "scope_checksum",
                                   "tool_permissions_hash",
                                   "platform_permissions_hash", "budget_state",
                                   "parent_mandate_id", "created_at",
                                   "activated_at", "expires_at", "ttl_seconds"}},
            )
            session.add(row)
            session.commit()
            return copy.deepcopy(mandate)

    def get(self, mandate_id: str) -> dict[str, Any] | None:
        with self._session() as session:
            row = session.get(MandateRow, mandate_id)
            return self._mandate_to_dict(row) if row else None

    def list_mandates(
        self,
        status: str | None = None,
        agent_id: str | None = None,
        project_id: str | None = None,
        governance_profile: str | None = None,
        cursor: str | None = None,
        limit: int = 20,
    ) -> tuple[list[dict[str, Any]], str | None, int]:
        with self._session() as session:
            query = select(MandateRow)

            if status:
                query = query.where(MandateRow.status == status)

            if agent_id:
                query = query.where(MandateRow.parties["subject"].as_string() == agent_id)

            if project_id:
                query = query.where(MandateRow.parties["project_id"].as_string() == project_id)

            if governance_profile:
                query = query.where(MandateRow.scope["governance_profile"].as_string() == governance_profile)

            total_query = select(func.count()).select_from(query.subquery())
            total = session.execute(total_query).scalar() or 0

            query = query.order_by(MandateRow.created_at.desc())

            if cursor:
                cursor_row = session.get(MandateRow, cursor)
                if cursor_row:
                    query = query.where(MandateRow.created_at < cursor_row.created_at)

            query = query.limit(limit)
            rows = session.execute(query).scalars().all()

            results = [self._mandate_to_dict(r) for r in rows]
            next_cursor = results[-1]["mandate_id"] if len(results) == limit else None

            return results, next_cursor, total

    def update_status(self, mandate_id: str, new_status: str, **kwargs: Any) -> dict[str, Any] | None:
        with self._session() as session:
            row = session.get(MandateRow, mandate_id)
            if not row:
                return None
            row.status = new_status
            if "activated_at" in kwargs:
                row.activated_at = kwargs["activated_at"]
            if "expires_at" in kwargs:
                row.expires_at = kwargs["expires_at"]
            extra = row.data or {}
            for k, v in kwargs.items():
                if k not in {"activated_at", "expires_at"}:
                    extra[k] = v
            row.data = extra
            session.commit()
            return self._mandate_to_dict(row)

    def update_budget(self, mandate_id: str, new_total_cents: int, new_remaining_cents: int) -> dict[str, Any] | None:
        with self._session() as session:
            row = session.get(MandateRow, mandate_id)
            if not row:
                return None
            budget = dict(row.budget_state or {})
            budget["total_cents"] = new_total_cents
            budget["remaining_cents"] = new_remaining_cents
            budget["consumed_cents"] = new_total_cents - new_remaining_cents
            row.budget_state = budget
            session.commit()
            return self._mandate_to_dict(row)

    def update_ttl(self, mandate_id: str, new_ttl_seconds: int, new_expires_at: str) -> dict[str, Any] | None:
        with self._session() as session:
            row = session.get(MandateRow, mandate_id)
            if not row:
                return None
            row.ttl_seconds = new_ttl_seconds
            row.expires_at = new_expires_at
            session.commit()
            return self._mandate_to_dict(row)

    def update_reservation(self, mandate_id: str, reserved_cents: int) -> dict[str, Any] | None:
        with self._session() as session:
            row = session.get(MandateRow, mandate_id)
            if not row:
                return None
            budget = dict(row.budget_state or {})
            budget["reserved_for_delegations_cents"] = reserved_cents
            row.budget_state = budget
            session.commit()
            return self._mandate_to_dict(row)

    def store_audit_record(self, record: dict[str, Any]) -> None:
        with self._session() as session:
            row = AuditRow(
                mandate_id=record.get("mandate_id", ""),
                operation=record.get("operation", ""),
                performed_by=record.get("performed_by", ""),
                timestamp=record.get("timestamp", ""),
                data=record,
            )
            session.add(row)
            session.commit()

    def get_audit_trail(self, mandate_id: str) -> list[dict[str, Any]]:
        with self._session() as session:
            rows = session.execute(
                select(AuditRow).where(AuditRow.mandate_id == mandate_id)
            ).scalars().all()
            return [r.data or {} for r in rows]

    def find_active_mandate(self, agent_id: str, project_id: str) -> dict[str, Any] | None:
        with self._session() as session:
            rows = session.execute(
                select(MandateRow).where(MandateRow.status == "ACTIVE")
            ).scalars().all()
            for row in rows:
                parties = row.parties or {}
                if parties.get("subject") == agent_id and parties.get("project_id") == project_id:
                    return self._mandate_to_dict(row)
            return None

    def get_children(self, parent_mandate_id: str) -> list[dict[str, Any]]:
        with self._session() as session:
            delegations = session.execute(
                select(DelegationRow).where(
                    DelegationRow.parent_mandate_id == parent_mandate_id
                )
            ).scalars().all()
            children = []
            for d in delegations:
                data = d.data or {}
                child_id = data.get("child_mandate_id", d.child_mandate_id)
                child_row = session.get(MandateRow, child_id)
                if child_row:
                    children.append(self._mandate_to_dict(child_row))
            return children

    def check_consumption_idempotency(self, enforcement_request_id: str) -> bool:
        with self._session() as session:
            row = session.get(ConsumptionRow, enforcement_request_id)
            return row is not None

    def record_consumption(self, mandate_id: str, enforcement_request_id: str, consumed_cents: int) -> None:
        with self._session() as session:
            row = ConsumptionRow(
                enforcement_request_id=enforcement_request_id,
                mandate_id=mandate_id,
                consumed_cents=consumed_cents,
                recorded_at=datetime.now(timezone.utc).isoformat(),
            )
            session.add(row)

            mandate_row = session.get(MandateRow, mandate_id)
            if mandate_row:
                budget = dict(mandate_row.budget_state or {})
                budget["remaining_cents"] = max(0, budget.get("remaining_cents", 0) - consumed_cents)
                budget["consumed_cents"] = budget.get("consumed_cents", 0) + consumed_cents
                mandate_row.budget_state = budget

            session.commit()

    def store_delegation(self, parent_id: str, child_id: str, delegation_info: dict[str, Any]) -> None:
        with self._session() as session:
            row = DelegationRow(
                parent_mandate_id=parent_id,
                child_mandate_id=child_id,
                data={"parent_mandate_id": parent_id, "child_mandate_id": child_id, **delegation_info},
            )
            session.add(row)
            session.commit()

    def get_delegation_chain(self, mandate_id: str) -> list[dict[str, Any]]:
        with self._session() as session:
            chain: list[dict[str, Any]] = []
            current_id = mandate_id
            visited: set[str] = set()

            while current_id and current_id not in visited:
                visited.add(current_id)
                row = session.execute(
                    select(DelegationRow).where(
                        DelegationRow.child_mandate_id == current_id
                    )
                ).scalars().first()
                if row:
                    data = row.data or {}
                    chain.insert(0, data)
                    current_id = row.parent_mandate_id
                else:
                    break

            return chain
