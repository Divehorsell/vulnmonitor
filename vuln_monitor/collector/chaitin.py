import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class ChaitinRiversCollector(BaseCollector):
    name = "Chaitin_Rivers"
    source_type = "cn_intel"
    base_url = "https://rivers.chaitin.cn/api/v1"

    def collect(self) -> list[dict]:
        results = []
        try:
            data = self.fetch_json(f"{self.base_url}/vulnerabilities", params={"page": 1, "per_page": 30})
            vulns = data.get("data", data.get("vulnerabilities", data if isinstance(data, list) else []))
            for item in vulns[:30]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", str(item.get("title", "")), re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else item.get("cve_id", "")

                raw = {
                    "cve_id": cve_id or f"CT-{item.get('id', '')}",
                    "title": item.get("title", ""),
                    "description": item.get("description", item.get("summary", "")),
                    "severity": self._map_severity(item.get("level", item.get("severity", ""))),
                    "publish_date": item.get("publish_date", item.get("published_at", "")),
                    "affected_products": item.get("product", ""),
                    "fix_recommendation": item.get("solution", ""),
                    "references": [item.get("url", "")],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[Chaitin_Rivers] Collection failed: {e}")

        logger.info(f"[Chaitin_Rivers] Collected {len(results)} advisories")
        return results

    @staticmethod
    def _map_severity(level: str) -> str:
        mapping = {"严重": "Critical", "高危": "High", "中危": "Medium", "低危": "Low"}
        return mapping.get(level, level if level in ("Critical", "High", "Medium", "Low") else "High")
