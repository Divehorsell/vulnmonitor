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
