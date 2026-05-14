import threading

import click
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from loguru import logger

from vuln_monitor.config.settings import settings
from vuln_monitor.storage.database import DatabaseManager
from vuln_monitor.collector.manager import CollectorManager


def run_scheduler():
    db = DatabaseManager()
    manager = CollectorManager(db)

    scheduler = BackgroundScheduler(
        job_defaults={
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 300,
        },
    )

    scheduler.add_job(
        manager.run_all,
        "interval",
        minutes=settings.crawl_interval,
        id="vuln_collect",
        name="Vulnerability Collection",
    )

    scheduler.start()
    logger.info(f"Scheduler started with {settings.crawl_interval}-minute interval")
    return scheduler


def run_web():
    from vuln_monitor.web.app import app

    uvicorn.run(
        app,
        host=settings.web_host,
        port=settings.web_port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )


@click.group()
def main():
    pass


@main.command()
def serve():
    scheduler = run_scheduler()
    try:
        logger.info("Starting VulnMonitor in serve mode (web + scheduler)")
        run_web()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown(wait=False)
        logger.info("VulnMonitor stopped")


@main.command()
def web():
    logger.info("Starting VulnMonitor web server only")
    run_web()


@main.command()
def scheduler():
    import time

    sched = run_scheduler()
    try:
        logger.info("Starting VulnMonitor scheduler only")
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        sched.shutdown(wait=False)
        logger.info("VulnMonitor scheduler stopped")


@main.command()
def fetch():
    db = DatabaseManager()
    manager = CollectorManager(db)
    logger.info("Running one-time vulnerability collection")
    count = manager.run_all()
    logger.info(f"One-time collection complete. {count} new vulnerabilities found.")


if __name__ == "__main__":
    main()
