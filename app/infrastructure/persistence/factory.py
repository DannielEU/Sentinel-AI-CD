"""
Repository factory — returns the appropriate RepositoryPort implementation
based on whether DATABASE_URL is configured.
"""

import asyncio
import logging
import os

logger = logging.getLogger(__name__)

_DB_RETRIES = 5
_DB_RETRY_DELAY = 3  # seconds between retries


async def create_repository():
    """Return a SQLRepository if DATABASE_URL is set, otherwise NullRepository."""
    database_url = os.getenv("DATABASE_URL", "").strip()

    if not database_url:
        from infrastructure.persistence.null_repository import NullRepository

        logger.info(
            "Database: not configured (DATABASE_URL not set) — "
            "history and whitelist disabled"
        )
        logger.info("Mode: rules + AI only, no persistence")
        return NullRepository()

    from infrastructure.persistence.sql_repository import SQLRepository

    last_exc: Exception | None = None
    for attempt in range(1, _DB_RETRIES + 1):
        try:
            repo = await SQLRepository.create(database_url)
            logger.info("Mode: DB enabled — history and whitelist active")
            return repo
        except Exception as exc:
            last_exc = exc
            if attempt < _DB_RETRIES:
                logger.warning(
                    "Database connection attempt %d/%d failed (%s) — retrying in %ds...",
                    attempt, _DB_RETRIES, exc, _DB_RETRY_DELAY,
                )
                await asyncio.sleep(_DB_RETRY_DELAY)

    from infrastructure.persistence.null_repository import NullRepository

    logger.error(
        "Database connection failed after %d attempts (%s) — "
        "falling back to NullRepository. History and whitelist disabled.",
        _DB_RETRIES, last_exc,
    )
    return NullRepository()
