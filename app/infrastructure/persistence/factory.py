"""
Repository factory — returns the appropriate RepositoryPort implementation
based on whether DATABASE_URL is configured.
"""

import logging
import os

logger = logging.getLogger(__name__)


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

    try:
        from infrastructure.persistence.sql_repository import SQLRepository

        repo = await SQLRepository.create(database_url)
        logger.info("Mode: DB enabled — history and whitelist active")
        return repo
    except Exception as exc:
        from infrastructure.persistence.null_repository import NullRepository

        logger.error(
            "Database connection failed (%s) — falling back to NullRepository. "
            "History and whitelist disabled.",
            exc,
        )
        return NullRepository()
