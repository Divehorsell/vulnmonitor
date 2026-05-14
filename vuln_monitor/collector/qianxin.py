import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class QiAnXinCollector(BaseCollector):
    name = "QiAnXin"
    source_type = "cn_intel"
    base_url = "https://ti.qianxin.com/api/v1"

    def collect(self) -> list[dict]:
        results = []
        try:
            data = self.fetch_json(f"{self.base_url}/vuln/list", params={"page": 1, "size": 30})
            vulns = data.get("data", data.get("list", []))
            for item in vulns[:30]:
                cve_id = item.get("cve_id", item.get("cveId", ""))
                raw = {
                    "cve_id": cve_id or f"QAX-{item.get('id', '')}",
                    "title": item.get("title", item.get("name", "")),
                    "description": item.get("description", item.get("detail", "")),
                    "severity": self._map_severity(item.get("level", item.get("severity", ""))),
                    "publish_date": item.get("publish_date", item.get("published_at", "")),
                    "affected_products": item.get("product", ""),
                    "fix_recommendation": item.get("solution", ""),
                    "references": [item.get("reference", item.get("url", ""))],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[QiAnXin] Collection failed: {e}")

        logger.info(f"[QiAnXin] Collected {len(results)} advisories")
        return results

    @staticmethod
    def _map_severity(level: str) -> str:
        mapping = {"严重": "Critical", "高危": "High", "中危": "Medium", "低危": "Low"}
        return mapping.get(level, level if level in ("Critical", "High", "Medium", "Low") else "High")
