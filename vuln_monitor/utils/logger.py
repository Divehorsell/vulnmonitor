import sys
from pathlib import Path

from loguru import logger

from vuln_monitor.config.settings import settings


def setup_logger():
    logger.remove()

    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    logger.add(
        sys.stderr,
        format=log_format,
        level=settings.log_level,
        colorize=True,
    )

    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.add(
        str(log_dir / "vulnmonitor.log"),
        format=log_format,
        level=settings.log_level,
        rotation=settings.log_rotation,
        retention=settings.log_retention,
        compression="gz",
        encoding="utf-8",
    )

    logger.add(
        str(log_dir / "error.log"),
        format=log_format,
        level="ERROR",
        rotation=settings.log_rotation,
        retention=settings.log_retention,
        compression="gz",
        encoding="utf-8",
    )

    return logger


setup_logger()
