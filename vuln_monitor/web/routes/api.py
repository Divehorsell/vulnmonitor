from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Request
from loguru import logger
from pydantic import BaseModel

from vuln_monitor.storage.database import DatabaseManager

api_router = APIRouter()


class ToggleSourceRequest(BaseModel):
    enabled: bool


def get_db(request: Request) -> DatabaseManager:
    return request.app.state.db


@api_router.get("/vulnerabilities")
async def list_vulnerabilities(
    request: Request,
    cve_id: Optional[str] = None,
    source: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    days: Optional[int] = None,
    pushed: Optional[bool] = None,
    limit: int = 50,
    offset: int = 0,
):
    db = get_db(request)
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
    return {"data": vulns, "count": len(vulns), "limit": limit, "offset": offset}


@api_router.get("/vulnerabilities/{cve_id}")
async def get_vulnerability(request: Request, cve_id: str):
    db = get_db(request)
    vuln = db.get_vulnerability(cve_id)
    if vuln is None:
        return {"error": "未找到该漏洞", "cve_id": cve_id}
    return {"data": vuln}


@api_router.get("/stats")
async def get_stats(request: Request):
    db = get_db(request)
    stats = db.get_stats()
    return {"data": stats}


@api_router.post("/fetch")
async def trigger_fetch(request: Request, background_tasks: BackgroundTasks):
    try:
        from vuln_monitor.collector.manager import CollectorManager

        db = get_db(request)

        def run_fetch():
            try:
                manager = CollectorManager(db)
                manager.run()
                logger.info("Manual fetch completed")
            except Exception as e:
                logger.error(f"Manual fetch failed: {e}")

        background_tasks.add_task(run_fetch)
        return {"message": "数据采集任务已启动", "status": "started"}
    except ImportError:
        return {"message": "采集模块尚未就绪", "status": "unavailable"}


@api_router.get("/sources")
async def list_sources(request: Request):
    db = get_db(request)
    sources = db.get_sources()
    return {"data": sources}


@api_router.put("/sources/{source_name}/toggle")
async def toggle_source(request: Request, source_name: str, body: ToggleSourceRequest):
    db = get_db(request)
    db.toggle_source(source_name, body.enabled)
    status_text = "已启用" if body.enabled else "已禁用"
    return {"message": f"数据源 {source_name} {status_text}", "source": source_name, "enabled": body.enabled}
