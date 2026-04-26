"""
NullRepository — no-op persistence adapter used when DATABASE_URL is not set.

All write operations are silently discarded (logged at DEBUG level).
All read operations return empty collections.
"""

import logging

from domain.entities import CVEException, ScanRecord

logger = logging.getLogger(__name__)


class NullRepository:
    """Satisfies RepositoryPort without any real storage."""

    @property
    def is_available(self) -> bool:
        return False

    async def save_scan(self, record: ScanRecord) -> None:
        logger.debug(
            "DB not configured — scan not persisted for %s", record.image_name
        )

    async def get_history(
        self, image_name: str, limit: int = 20
    ) -> list[ScanRecord]:
        return []

    async def get_all_recent(self, limit: int = 50) -> list[ScanRecord]:
        return []

    async def get_active_exceptions(self) -> list[CVEException]:
        return []

    async def add_exception(self, exc: CVEException) -> None:
        logger.debug(
            "DB not configured — CVE exception not persisted: %s", exc.cve_id
        )

    async def delete_exception(self, cve_id: str) -> None:
        logger.debug(
            "DB not configured — delete exception ignored: %s", cve_id
        )
