import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Request
from loguru import logger
from pydantic import BaseModel

from vuln_monitor.config.settings import settings
from vuln_monitor.storage.database import DatabaseManager

api_router = APIRouter()


class ToggleSourceRequest(BaseModel):
    enabled: bool


class CliRequest(BaseModel):
    command: str


class SettingsRequest(BaseModel):
    settings: dict = {}


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
                manager.run_all()
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


@api_router.get("/poc-search")
async def poc_search(request: Request, q: str = ""):
    if not q:
        return {"results": []}

    try:
        from vuln_monitor.poc_search.github_finder import GitHubPoCFinder

        finder = GitHubPoCFinder(github_token=settings.github_token)
        if q.upper().startswith("CVE-"):
            results = finder.search(q)
        else:
            results = finder.search_by_keyword(q)
        return {"results": results}
    except Exception as e:
        logger.error(f"PoC search failed: {e}")
        return {"results": [], "error": str(e)}


@api_router.get("/reports/generate")
async def generate_report(request: Request, type: str = "weekly", days: int = 7):
    db = get_db(request)
    try:
        from vuln_monitor.reporter.markdown_reporter import MarkdownReporter

        reporter = MarkdownReporter(db)
        if type == "weekly":
            content = reporter.generate_weekly_report()
            name = "漏洞周报"
        elif type == "monthly":
            content = reporter.generate_monthly_report()
            name = "漏洞月报"
        else:
            content = reporter.generate_custom_report(days)
            name = f"漏洞报告（{days}天）"

        return {"content": content, "name": name}
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return {"message": f"报告生成失败: {str(e)}"}


@api_router.post("/cli")
async def execute_cli(request: Request, body: CliRequest):
    cmd = body.command.strip()
    if not cmd:
        return {"error": "命令不能为空"}

    allowed_prefixes = ("stats", "query", "brief", "config show", "config set")
    if not any(cmd.startswith(prefix) for prefix in allowed_prefixes):
        return {"error": f"不允许的命令。允许的命令: {', '.join(allowed_prefixes)}"}

    try:
        result = subprocess.run(
            ["python", "-m", "vuln_monitor.cli.commands"] + cmd.split(),
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(Path(__file__).parent.parent.parent.parent),
        )
        output = result.stdout if result.stdout else result.stderr
        return {"output": output}
    except subprocess.TimeoutExpired:
        return {"error": "命令执行超时"}
    except Exception as e:
        return {"error": str(e)}


@api_router.put("/settings")
async def update_settings(request: Request, body: dict = {}):
    env_path = Path(settings.db_path).parent.parent / ".env"
    existing_lines = []
    if env_path.exists():
        with open(env_path, "r") as f:
            existing_lines = f.readlines()

    existing_keys = {}
    for i, line in enumerate(existing_lines):
        if "=" in line and not line.strip().startswith("#"):
            key = line.split("=")[0].strip()
            existing_keys[key] = i

    for key, value in body.items():
        if value is None or value == "":
            continue
        env_key = key.upper()
        line = f"{env_key}={value}\n"
        if env_key in existing_keys:
            existing_lines[existing_keys[env_key]] = line
        else:
            existing_lines.append(line)

    with open(env_path, "w") as f:
        f.writelines(existing_lines)

    return {"message": "配置已保存，部分设置需重启生效"}


@api_router.post("/maintenance/cleanup")
async def cleanup_data(request: Request):
    db = get_db(request)
    db.cleanup_old_records(settings.dedup_ttl_days)
    return {"message": f"已清理 {settings.dedup_ttl_days} 天前的过期记录"}


@api_router.post("/maintenance/rebuild")
async def rebuild_database(request: Request):
    db_path = Path(settings.db_path)
    if db_path.exists():
        db_path.unlink()
    db = get_db(request)
    from vuln_monitor.storage.database import DatabaseManager
    new_db = DatabaseManager()
    request.app.state.db = new_db
    return {"message": "数据库已重建"}


class HistoryCollectRequest(BaseModel):
    start_date: str
    end_date: str
    sources: list[str] = []
    skip_push: bool = True
    include_non_rce: bool = False


@api_router.post("/history/collect")
async def history_collect(request: Request, background_tasks: BackgroundTasks, body: HistoryCollectRequest):
    try:
        from vuln_monitor.collector.manager import CollectorManager, _history_tasks, _history_lock
        import uuid

        db = get_db(request)
        task_id = str(uuid.uuid4())[:8]

        with _history_lock:
            _history_tasks[task_id] = {
                "task_id": task_id,
                "status": "pending",
                "progress": 0,
                "start_date": body.start_date,
                "end_date": body.end_date,
                "sources": ", ".join(body.sources) if body.sources else "全部",
                "collected": 0,
                "new_count": 0,
                "logs": [],
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            }

        def run_history():
            try:
                manager = CollectorManager(db)
                manager.run_history(
                    start_date=body.start_date,
                    end_date=body.end_date,
                    source_names=body.sources if body.sources else None,
                    skip_push=body.skip_push,
                    include_non_rce=body.include_non_rce,
                    task_id=task_id,
                )
            except Exception as e:
                logger.error(f"History collection failed: {e}")
                with _history_lock:
                    _history_tasks[task_id]["status"] = "failed"
                    _history_tasks[task_id]["error"] = str(e)

        background_tasks.add_task(run_history)

        return {
            "task_id": task_id,
            "message": f"历史收集任务已启动: {body.start_date} ~ {body.end_date}",
            "status": "started",
        }
    except ImportError:
        return {"message": "采集模块尚未就绪", "status": "unavailable"}


@api_router.get("/history/progress/{task_id}")
async def history_progress(task_id: str):
    from vuln_monitor.collector.manager import get_history_task
    task = get_history_task(task_id)
    if not task:
        return {"task_id": task_id, "status": "not_found", "progress": 0}
    return task
