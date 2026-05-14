from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from vuln_monitor.storage.database import DatabaseManager
from vuln_monitor.config.settings import settings

pages_router = APIRouter()


def get_db(request: Request) -> DatabaseManager:
    return request.app.state.db


def get_templates(request: Request):
    return request.app.state.templates


@pages_router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    db = get_db(request)
    templates = get_templates(request)
    stats = db.get_stats()
    recent = db.query_vulnerabilities(limit=10, offset=0)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "stats": stats, "recent_vulns": recent},
    )


@pages_router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerability_list(
    request: Request,
    cve_id: Optional[str] = None,
    source: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    days: Optional[int] = None,
    pushed: Optional[bool] = None,
    limit: int = 20,
    offset: int = 0,
):
    db = get_db(request)
    templates = get_templates(request)
    vulns = db.query_vulnerabilities(
        cve_id=cve_id,
        source=source,
        keyword=keyword,
        severity=severity,
        days=days,
        pushed=pushed,
        limit=limit,
        offset=offset,
    )
    stats = db.get_stats()
    sources = list(stats.get("source_distribution", {}).keys())

    is_htmx = request.headers.get("HX-Request", "").lower() == "true"

    if is_htmx:
        return templates.TemplateResponse(
            "partials/vuln_cards.html",
            {
                "request": request,
                "vulns": vulns,
                "limit": limit,
                "offset": offset,
                "has_more": len(vulns) == limit,
            },
        )

    return templates.TemplateResponse(
        "vulnerabilities.html",
        {
            "request": request,
            "vulns": vulns,
            "sources": sources,
            "limit": limit,
            "offset": offset,
            "has_more": len(vulns) == limit,
            "filters": {
                "cve_id": cve_id or "",
                "source": source or "",
                "keyword": keyword or "",
                "severity": severity or "",
                "days": days or "",
                "pushed": pushed,
            },
        },
    )


@pages_router.get("/vulnerabilities/{cve_id}", response_class=HTMLResponse)
async def vulnerability_detail(request: Request, cve_id: str):
    db = get_db(request)
    templates = get_templates(request)
    vuln = db.get_vulnerability(cve_id)
    if vuln is None:
        return templates.TemplateResponse(
            "vuln_detail.html",
            {"request": request, "vuln": None, "cve_id": cve_id},
        )
    return templates.TemplateResponse(
        "vuln_detail.html",
        {"request": request, "vuln": vuln},
    )


@pages_router.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request):
    db = get_db(request)
    templates = get_templates(request)
    sources = db.get_sources()
    return templates.TemplateResponse(
        "sources.html",
        {"request": request, "sources": sources},
    )


@pages_router.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    db = get_db(request)
    templates = get_templates(request)
    sources = db.get_sources()
    return templates.TemplateResponse(
        "tasks.html",
        {"request": request, "sources": sources, "crawl_interval": settings.crawl_interval},
    )


@pages_router.get("/poc-search", response_class=HTMLResponse)
async def poc_search_page(request: Request):
    templates = get_templates(request)
    return templates.TemplateResponse(
        "poc_search.html",
        {"request": request},
    )


@pages_router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    db = get_db(request)
    templates = get_templates(request)
    from pathlib import Path
    report_dir = Path(settings.db_path).parent / "reports"
    reports = []
    if report_dir.exists():
        for f in sorted(report_dir.glob("*.md"), reverse=True)[:20]:
            reports.append({
                "name": f.stem.replace("_", " ").replace("-", "/"),
                "date": f.stem.split("_")[-1] if "_" in f.stem else "",
                "filename": f.name,
            })
    return templates.TemplateResponse(
        "reports.html",
        {"request": request, "reports": reports},
    )


@pages_router.get("/cli", response_class=HTMLResponse)
async def cli_page(request: Request):
    templates = get_templates(request)
    return templates.TemplateResponse(
        "cli.html",
        {"request": request},
    )


@pages_router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    templates = get_templates(request)
    config = settings.model_dump()
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "config": config},
    )


@pages_router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    db = get_db(request)
    templates = get_templates(request)
    sources = db.get_sources()
    from vuln_monitor.collector.manager import get_all_history_tasks
    history_records = get_all_history_tasks()
    return templates.TemplateResponse(
        "history.html",
        {"request": request, "sources": sources, "history_records": history_records},
    )
