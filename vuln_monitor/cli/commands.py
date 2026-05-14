import json
from datetime import datetime, timedelta

import click
from loguru import logger
from tabulate import tabulate

from vuln_monitor.storage.database import DatabaseManager
from vuln_monitor.collector.manager import CollectorManager
from vuln_monitor.processor.deduplicator import Deduplicator
from vuln_monitor.processor.filter_engine import FilterEngine
from vuln_monitor.processor.scorer import Scorer
from vuln_monitor.notifier.telegram import TelegramNotifier
from vuln_monitor.notifier.dingtalk import DingTalkNotifier
from vuln_monitor.notifier.wecom import WeComNotifier
from vuln_monitor.notifier.feishu import FeishuNotifier
from vuln_monitor.notifier.email import EmailNotifier
from vuln_monitor.config.settings import settings


@click.group()
def cli():
    pass


@cli.command()
@click.option("--dry-run", is_flag=True, default=False, help="Dry run mode, do not push notifications")
def fetch(dry_run):
    db = DatabaseManager()
    manager = CollectorManager(db)
    if dry_run:
        click.echo("Dry run mode: collecting without pushing notifications")
    count = manager.run_all(push=not dry_run)
    click.echo(f"Collection complete. {count} new vulnerabilities found.")


@cli.command()
@click.option("--cve", default=None, help="Filter by CVE ID")
@click.option("--source", default=None, help="Filter by source name")
@click.option("--keyword", default=None, help="Search keyword in title/description")
@click.option("--severity", default=None, type=click.Choice(["Critical", "High", "Medium", "Low"]), help="Filter by severity")
@click.option("--days", default=None, type=int, help="Filter by recent N days")
@click.option("--pushed", default=None, type=click.Choice(["true", "false"]), help="Filter by pushed status")
@click.option("--format", "output_format", default="table", type=click.Choice(["json", "table", "markdown"]), help="Output format")
def query(cve, source, keyword, severity, days, pushed, output_format):
    db = DatabaseManager()
    pushed_val = None
    if pushed == "true":
        pushed_val = True
    elif pushed == "false":
        pushed_val = False

    results = db.query_vulnerabilities(
        cve_id=cve,
        source=source,
        keyword=keyword,
        severity=severity,
        days=days,
        pushed=pushed_val,
        limit=100,
    )

    if not results:
        click.echo("No vulnerabilities found matching the criteria.")
        return

    if output_format == "json":
        click.echo(json.dumps(results, ensure_ascii=False, indent=2, default=str))
    elif output_format == "markdown":
        click.echo("| CVE ID | Title | Severity | Source | Score | Pushed |")
        click.echo("|--------|-------|----------|--------|-------|--------|")
        for v in results:
            click.echo(f"| {v.get('cve_id', '')} | {v.get('title', '')} | {v.get('severity', '')} | {v.get('source', '')} | {v.get('quality_score', 0)} | {'Yes' if v.get('pushed') else 'No'} |")
    else:
        headers = ["CVE ID", "Title", "Severity", "Source", "Score", "Pushed", "Publish Date"]
        rows = []
        for v in results:
            rows.append([
                v.get("cve_id", ""),
                v.get("title", "")[:60],
                v.get("severity", ""),
                v.get("source", ""),
                v.get("quality_score", 0),
                "Yes" if v.get("pushed") else "No",
                v.get("publish_date", ""),
            ])
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))


@cli.command()
@click.option("--pushed", default=None, type=click.Choice(["true", "false"]), help="Filter by pushed status")
@click.option("--days", default=1, type=int, help="Recent N days")
def brief(pushed, days):
    db = DatabaseManager()
    pushed_val = None
    if pushed == "true":
        pushed_val = True
    elif pushed == "false":
        pushed_val = False

    results = db.query_vulnerabilities(
        pushed=pushed_val,
        days=days,
        limit=200,
    )

    if not results:
        click.echo(f"No vulnerabilities found in the last {days} day(s).")
        return

    critical = [v for v in results if v.get("severity") == "Critical"]
    high = [v for v in results if v.get("severity") == "High"]
    poc_available = [v for v in results if v.get("poc_available")]
    kev_marked = [v for v in results if v.get("kev_marked")]

    click.echo(f"=== Vulnerability Brief (Last {days} day(s)) ===")
    click.echo(f"Total: {len(results)}")
    click.echo(f"Critical: {len(critical)} | High: {len(high)}")
    click.echo(f"PoC Available: {len(poc_available)} | KEV Marked: {len(kev_marked)}")
    click.echo()

    if critical:
        click.echo("--- Critical Vulnerabilities ---")
        for v in critical[:10]:
            click.echo(f"  [{v.get('cve_id', '')}] {v.get('title', '')} (Source: {v.get('source', '')}, Score: {v.get('quality_score', 0)})")
        if len(critical) > 10:
            click.echo(f"  ... and {len(critical) - 10} more")
        click.echo()

    if high:
        click.echo("--- High Severity Vulnerabilities ---")
        for v in high[:10]:
            click.echo(f"  [{v.get('cve_id', '')}] {v.get('title', '')} (Source: {v.get('source', '')}, Score: {v.get('quality_score', 0)})")
        if len(high) > 10:
            click.echo(f"  ... and {len(high) - 10} more")
        click.echo()

    if poc_available:
        click.echo("--- PoC Available ---")
        for v in poc_available[:10]:
            click.echo(f"  [{v.get('cve_id', '')}] {v.get('title', '')} (Score: {v.get('quality_score', 0)})")
        if len(poc_available) > 10:
            click.echo(f"  ... and {len(poc_available) - 10} more")


@cli.command()
def stats():
    db = DatabaseManager()
    stat = db.get_stats()

    click.echo("=== Vulnerability Statistics ===")
    click.echo(f"Total: {stat['total']}")
    click.echo(f"Today: {stat['today']}")
    click.echo(f"Pushed: {stat['pushed']} | Unpushed: {stat['unpushed']}")
    click.echo()

    if stat.get("severity_distribution"):
        click.echo("--- Severity Distribution ---")
        for sev, count in sorted(stat["severity_distribution"].items(), key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x[0], 99)):
            click.echo(f"  {sev}: {count}")
        click.echo()

    if stat.get("source_distribution"):
        click.echo("--- Source Distribution ---")
        for source, count in sorted(stat["source_distribution"].items(), key=lambda x: x[1], reverse=True):
            click.echo(f"  {source}: {count}")

    sources = db.get_sources()
    if sources:
        click.echo()
        click.echo("--- Source Status ---")
        for s in sources:
            status_icon = "✅" if s.get("enabled") else "❌"
            last_crawl = s.get("last_crawl", "Never")
            click.echo(f"  {status_icon} {s['name']} (Last crawl: {last_crawl})")


@cli.command()
@click.option("--days", default=30, type=int, help="Number of days to backfill")
def rebuild(days):
    db = DatabaseManager()
    manager = CollectorManager(db)
    click.echo(f"Starting backfill for the last {days} days...")
    count = manager.run_all(push=False)
    click.echo(f"Backfill complete. {count} vulnerabilities processed.")


@cli.group()
def config():
    pass


@config.command("show")
def config_show():
    config_data = settings.model_dump()
    for key, value in sorted(config_data.items()):
        if any(sensitive in key.lower() for sensitive in ["token", "secret", "password", "key"]):
            if value:
                value = "***REDACTED***"
        click.echo(f"{key} = {value}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    env_path = settings.data_dir.parent / ".env"
    lines = []
    key_found = False

    if env_path.exists():
        with open(env_path, "r") as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                key_found = True
                break

    if not key_found:
        lines.append(f"{key}={value}\n")

    with open(env_path, "w") as f:
        f.writelines(lines)

    click.echo(f"Set {key}={value} in {env_path}")
    click.echo("Restart the application for changes to take effect.")
