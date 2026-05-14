import uuid
from datetime import datetime, timedelta
from threading import Lock

from loguru import logger

from vuln_monitor.storage.database import DatabaseManager
from vuln_monitor.collector.cisa import CISACollector
from vuln_monitor.collector.github_poc import GitHubPoCCollector
from vuln_monitor.collector.sploitus import SploitusCollector
from vuln_monitor.collector.zdi import ZDICollector
from vuln_monitor.collector.fortinet import FortinetCollector
from vuln_monitor.collector.paloalto import PaloAltoCollector
from vuln_monitor.collector.cisco import CiscoCollector
from vuln_monitor.collector.microsoft_msrc import MicrosoftMSRCCollector
from vuln_monitor.collector.watchtowr import WatchTowrCollector
from vuln_monitor.collector.daily_cve import DailyCVECollector
from vuln_monitor.collector.horizon3 import Horizon3Collector
from vuln_monitor.collector.rapid7 import Rapid7Collector
from vuln_monitor.collector.qianxin import QiAnXinCollector
from vuln_monitor.collector.chaitin import ChaitinRiversCollector
from vuln_monitor.collector.threatbook import ThreatBookCollector
from vuln_monitor.collector.oscs import OSCSCollector
from vuln_monitor.processor.deduplicator import Deduplicator
from vuln_monitor.processor.filter_engine import FilterEngine
from vuln_monitor.processor.scorer import Scorer
from vuln_monitor.notifier.telegram import TelegramNotifier
from vuln_monitor.notifier.dingtalk import DingTalkNotifier
from vuln_monitor.notifier.wecom import WeComNotifier
from vuln_monitor.notifier.feishu import FeishuNotifier
from vuln_monitor.notifier.email import EmailNotifier
from vuln_monitor.config.settings import settings


COLLECTOR_CLASSES = [
    CISACollector,
    GitHubPoCCollector,
    SploitusCollector,
    ZDICollector,
    FortinetCollector,
    PaloAltoCollector,
    CiscoCollector,
    MicrosoftMSRCCollector,
    WatchTowrCollector,
    DailyCVECollector,
    Horizon3Collector,
    Rapid7Collector,
    QiAnXinCollector,
    ChaitinRiversCollector,
    ThreatBookCollector,
    OSCSCollector,
]


_history_tasks: dict = {}
_history_lock = Lock()


class CollectorManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.deduplicator = Deduplicator(db)
        self.filter_engine = FilterEngine()
        self.scorer = Scorer()
        self.collectors: dict[str, object] = {}
        self.notifiers = []
        self._init_notifiers()
        self.register_collectors()

    def _init_notifiers(self):
        self.notifiers = [
            TelegramNotifier(self.db),
            DingTalkNotifier(self.db),
            WeComNotifier(self.db),
            FeishuNotifier(self.db),
            EmailNotifier(self.db),
        ]

    def register_collectors(self):
        for collector_cls in COLLECTOR_CLASSES:
            try:
                instance = collector_cls()
                self.collectors[instance.name] = instance
                self.db.upsert_source({
                    "name": instance.name,
                    "type": instance.source_type,
                    "url": instance.base_url,
                    "enabled": True,
                    "crawl_interval": settings.crawl_interval,
                    "status": "active",
                })
            except Exception as e:
                logger.error(f"Failed to register collector {collector_cls.__name__}: {e}")

    def _process_vulnerabilities(self, raw_vulns: list[dict]) -> list[dict]:
        unique = self.deduplicator.deduplicate(raw_vulns)
        filtered = self.filter_engine.filter(unique, rce_only=True)
        scored = self.scorer.score_vulnerabilities(filtered)
        return scored

    def _push_vulnerabilities(self, vulns: list[dict]):
        if not settings.push_enabled:
            logger.info("Push notifications disabled, skipping")
            return

        unpushed = [v for v in vulns if not v.get("pushed", False)]
        threshold = settings.push_score_threshold

        for vuln in unpushed:
            if vuln.get("quality_score", 0) < threshold:
                continue

            for notifier in self.notifiers:
                if notifier.is_configured():
                    try:
                        notifier.notify(vuln)
                    except Exception as e:
                        logger.error(f"[{notifier.channel}] Push failed for {vuln.get('cve_id', '')}: {e}")

            self.db.mark_pushed(vuln.get("cve_id", ""))

    def _store_vulnerabilities(self, vulns: list[dict]) -> int:
        stored = 0
        for vuln in vulns:
            try:
                if self.db.insert_vulnerability(vuln):
                    stored += 1
            except Exception as e:
                logger.error(f"Failed to store {vuln.get('cve_id', '')}: {e}")
        return stored

    def run_all(self, push: bool = True) -> int:
        all_raw = []
        total_new = 0

        for name, collector in self.collectors.items():
            try:
                logger.info(f"Running collector: {name}")
                raw_vulns = collector.collect()
                all_raw.extend(raw_vulns)
                self.db.update_source_last_crawl(name)
                logger.info(f"[{name}] Collected {len(raw_vulns)} raw vulnerabilities")
            except Exception as e:
                logger.error(f"[{name}] Collection failed: {e}")

        logger.info(f"Total raw vulnerabilities collected: {len(all_raw)}")

        processed = self._process_vulnerabilities(all_raw)
        logger.info(f"After processing: {len(processed)} vulnerabilities")

        stored = self._store_vulnerabilities(processed)
        total_new = stored
        logger.info(f"Stored {stored} new vulnerabilities")

        if push and processed:
            self._push_vulnerabilities(processed)

        for collector in self.collectors.values():
            try:
                collector.close()
            except Exception:
                pass

        return total_new

    def run_source(self, source_name: str) -> int:
        collector = self.collectors.get(source_name)
        if not collector:
            logger.error(f"Unknown source: {source_name}")
            available = ", ".join(self.collectors.keys())
            logger.info(f"Available sources: {available}")
            return 0

        try:
            logger.info(f"Running collector: {source_name}")
            raw_vulns = collector.collect()
            self.db.update_source_last_crawl(source_name)
            logger.info(f"[{source_name}] Collected {len(raw_vulns)} raw vulnerabilities")

            processed = self._process_vulnerabilities(raw_vulns)
            stored = self._store_vulnerabilities(processed)
            logger.info(f"Stored {stored} new vulnerabilities")

            if processed:
                self._push_vulnerabilities(processed)

            collector.close()
            return stored
        except Exception as e:
            logger.error(f"[{source_name}] Collection failed: {e}")
            return 0

    def run_history(
        self,
        start_date: str,
        end_date: str,
        source_names: list[str] = None,
        skip_push: bool = True,
        include_non_rce: bool = False,
        task_id: str = None,
    ) -> dict:
        if source_names is None:
            source_names = list(self.collectors.keys())

        task_id = task_id or str(uuid.uuid4())[:8]
        total_sources = len(source_names)
        all_raw = []
        total_new = 0
        logs = []

        def add_log(msg_type, msg):
            logs.append({"type": msg_type, "message": msg})
            with _history_lock:
                if task_id in _history_tasks:
                    _history_tasks[task_id]["logs"] = logs[-100:]

        add_log("info", f"开始历史漏洞收集: {start_date} ~ {end_date}, 共 {total_sources} 个数据源")

        with _history_lock:
            _history_tasks[task_id] = {
                "task_id": task_id,
                "status": "running",
                "progress": 0,
                "start_date": start_date,
                "end_date": end_date,
                "sources": ", ".join(source_names),
                "collected": 0,
                "new_count": 0,
                "logs": logs,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            }

        for i, name in enumerate(source_names):
            collector = self.collectors.get(name)
            if not collector:
                add_log("warning", f"未知数据源: {name}, 跳过")
                continue

            try:
                add_log("info", f"[{i+1}/{total_sources}] 正在采集 {name}...")
                with _history_lock:
                    _history_tasks[task_id]["progress"] = int((i / total_sources) * 80)

                raw_vulns = collector.collect()

                filtered_by_date = []
                for v in raw_vulns:
                    pub_date = v.get("publish_date", "")
                    if pub_date:
                        try:
                            pub_date_short = pub_date[:10]
                            if start_date <= pub_date_short <= end_date:
                                filtered_by_date.append(v)
                        except (ValueError, TypeError):
                            filtered_by_date.append(v)
                    else:
                        filtered_by_date.append(v)

                all_raw.extend(filtered_by_date)
                add_log("info", f"[{name}] 采集到 {len(raw_vulns)} 条, 日期范围内 {len(filtered_by_date)} 条")
                self.db.update_source_last_crawl(name)
            except Exception as e:
                add_log("error", f"[{name}] 采集失败: {e}")

        with _history_lock:
            _history_tasks[task_id]["progress"] = 85
        add_log("info", f"原始数据共 {len(all_raw)} 条, 开始去重/过滤/评分...")

        unique = self.deduplicator.deduplicate(all_raw)
        filtered = self.filter_engine.filter(unique, rce_only=not include_non_rce)
        scored = self.scorer.score_vulnerabilities(filtered)

        with _history_lock:
            _history_tasks[task_id]["progress"] = 95
        add_log("info", f"处理后 {len(scored)} 条漏洞, 开始存储...")

        stored = self._store_vulnerabilities(scored)
        total_new = stored

        if not skip_push and scored:
            self._push_vulnerabilities(scored)

        for collector in self.collectors.values():
            try:
                collector.close()
            except Exception:
                pass

        with _history_lock:
            _history_tasks[task_id]["status"] = "completed"
            _history_tasks[task_id]["progress"] = 100
            _history_tasks[task_id]["collected"] = len(all_raw)
            _history_tasks[task_id]["new_count"] = total_new

        add_log("success", f"历史收集完成! 共收集 {len(all_raw)} 条, 新增 {total_new} 条")
        logger.info(f"History collection completed: {len(all_raw)} collected, {total_new} new")

        return _history_tasks[task_id]


def get_history_task(task_id: str) -> dict:
    with _history_lock:
        return _history_tasks.get(task_id, {"task_id": task_id, "status": "unknown", "progress": 0})


def get_all_history_tasks() -> list[dict]:
    with _history_lock:
        return list(_history_tasks.values())
