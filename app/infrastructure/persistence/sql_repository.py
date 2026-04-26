"""
SQLRepository — async persistence adapter for SQLite and PostgreSQL.

Supported DATABASE_URL formats:
  SQLite:     sqlite+aiosqlite:///./data/sentinel.db
  PostgreSQL: postgresql+asyncpg://user:pass@host:5432/dbname

Tables are created automatically on first use (CREATE TABLE IF NOT EXISTS).
Schema is also documented in schema.sql at the repository root.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from domain.entities import CVEException, ScanRecord

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS scan_history (
    id             INTEGER   PRIMARY KEY AUTOINCREMENT,
    image_name     TEXT      NOT NULL,
    decision       TEXT      NOT NULL,
    reason         TEXT      NOT NULL,
    source         TEXT      NOT NULL,
    critical_vulns INTEGER   DEFAULT 0,
    high_vulns     INTEGER   DEFAULT 0,
    medium_vulns   INTEGER   DEFAULT 0,
    low_vulns      INTEGER   DEFAULT 0,
    image_size_mb  REAL      DEFAULT 0,
    secrets_found  INTEGER   DEFAULT 0,
    ai_provider    TEXT,
    scanned_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_exceptions (
    id          INTEGER   PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT      NOT NULL UNIQUE,
    reason      TEXT      NOT NULL,
    approved_by TEXT,
    expires_at  TIMESTAMP,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active   INTEGER   DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_scan_history_image      ON scan_history(image_name);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at);
CREATE INDEX IF NOT EXISTS idx_cve_exceptions_cve_id   ON cve_exceptions(cve_id);
"""

# PostgreSQL needs different DDL (SERIAL instead of AUTOINCREMENT)
_DDL_PG = """
CREATE TABLE IF NOT EXISTS scan_history (
    id             SERIAL    PRIMARY KEY,
    image_name     TEXT      NOT NULL,
    decision       TEXT      NOT NULL,
    reason         TEXT      NOT NULL,
    source         TEXT      NOT NULL,
    critical_vulns INTEGER   DEFAULT 0,
    high_vulns     INTEGER   DEFAULT 0,
    medium_vulns   INTEGER   DEFAULT 0,
    low_vulns      INTEGER   DEFAULT 0,
    image_size_mb  REAL      DEFAULT 0,
    secrets_found  INTEGER   DEFAULT 0,
    ai_provider    TEXT,
    scanned_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_exceptions (
    id          SERIAL    PRIMARY KEY,
    cve_id      TEXT      NOT NULL UNIQUE,
    reason      TEXT      NOT NULL,
    approved_by TEXT,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    is_active   INTEGER   DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_scan_history_image      ON scan_history(image_name);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at);
CREATE INDEX IF NOT EXISTS idx_cve_exceptions_cve_id   ON cve_exceptions(cve_id);
"""


def _row_to_scan(row: Any) -> ScanRecord:
    scanned_at = row.scanned_at
    if isinstance(scanned_at, str):
        try:
            scanned_at = datetime.fromisoformat(scanned_at)
        except ValueError:
            scanned_at = None
    return ScanRecord(
        id=row.id,
        image_name=row.image_name,
        decision=row.decision,
        reason=row.reason,
        source=row.source,
        critical_vulns=row.critical_vulns or 0,
        high_vulns=row.high_vulns or 0,
        medium_vulns=row.medium_vulns or 0,
        low_vulns=row.low_vulns or 0,
        image_size_mb=row.image_size_mb or 0.0,
        secrets_found=row.secrets_found or 0,
        ai_provider=row.ai_provider,
        scanned_at=scanned_at,
    )


def _row_to_exc(row: Any) -> CVEException:
    def _dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val)
            except ValueError:
                return None
        return val

    return CVEException(
        id=row.id,
        cve_id=row.cve_id,
        reason=row.reason,
        approved_by=row.approved_by,
        expires_at=_dt(row.expires_at),
        created_at=_dt(row.created_at),
        is_active=bool(row.is_active),
    )


class SQLRepository:
    def __init__(self, engine: AsyncEngine, session_factory: Any) -> None:
        self._engine = engine
        self._session_factory = session_factory

    @property
    def is_available(self) -> bool:
        return True

    @classmethod
    async def create(cls, database_url: str) -> "SQLRepository":
        is_pg = database_url.startswith("postgresql")
        engine = create_async_engine(database_url, echo=False, future=True)
        session_factory = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        ddl = _DDL_PG if is_pg else _DDL
        async with engine.begin() as conn:
            for statement in ddl.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
        logger.info("Database connected: %s", database_url)
        logger.info("Tables verified: scan_history, cve_exceptions")
        return cls(engine, session_factory)

    async def save_scan(self, record: ScanRecord) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    "INSERT INTO scan_history "
                    "(image_name, decision, reason, source, critical_vulns, high_vulns, "
                    "medium_vulns, low_vulns, image_size_mb, secrets_found, ai_provider) "
                    "VALUES (:image_name, :decision, :reason, :source, :critical_vulns, "
                    ":high_vulns, :medium_vulns, :low_vulns, :image_size_mb, "
                    ":secrets_found, :ai_provider)"
                ),
                {
                    "image_name": record.image_name,
                    "decision": record.decision,
                    "reason": record.reason,
                    "source": record.source,
                    "critical_vulns": record.critical_vulns,
                    "high_vulns": record.high_vulns,
                    "medium_vulns": record.medium_vulns,
                    "low_vulns": record.low_vulns,
                    "image_size_mb": record.image_size_mb,
                    "secrets_found": record.secrets_found,
                    "ai_provider": record.ai_provider,
                },
            )
            await session.commit()

    async def get_history(
        self, image_name: str, limit: int = 20
    ) -> list[ScanRecord]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT * FROM scan_history WHERE image_name = :name "
                    "ORDER BY scanned_at DESC LIMIT :limit"
                ),
                {"name": image_name, "limit": limit},
            )
            return [_row_to_scan(r) for r in result.mappings().all()]

    async def get_all_recent(self, limit: int = 50) -> list[ScanRecord]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT :limit"
                ),
                {"limit": limit},
            )
            return [_row_to_scan(r) for r in result.mappings().all()]

    async def get_active_exceptions(self) -> list[CVEException]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT * FROM cve_exceptions WHERE is_active = 1 "
                    "AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
                )
            )
            return [_row_to_exc(r) for r in result.mappings().all()]

    async def add_exception(self, exc: CVEException) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    "INSERT INTO cve_exceptions (cve_id, reason, approved_by, expires_at) "
                    "VALUES (:cve_id, :reason, :approved_by, :expires_at) "
                    "ON CONFLICT(cve_id) DO UPDATE SET "
                    "reason=excluded.reason, approved_by=excluded.approved_by, "
                    "expires_at=excluded.expires_at, is_active=1"
                ),
                {
                    "cve_id": exc.cve_id.upper(),
                    "reason": exc.reason,
                    "approved_by": exc.approved_by,
                    "expires_at": exc.expires_at,
                },
            )
            await session.commit()

    async def delete_exception(self, cve_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    "UPDATE cve_exceptions SET is_active = 0 WHERE cve_id = :cve_id"
                ),
                {"cve_id": cve_id.upper()},
            )
            await session.commit()
