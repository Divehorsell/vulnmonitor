import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class DailyCVECollector(BaseCollector):
    name = "DailyCVE"
    source_type = "disclosure"
    base_url = "https://cve.circl.lu/api"

    def collect(self) -> list[dict]:
        results = []
        try:
            data = self.fetch_json(f"{self.base_url}/last")
            for item in data[:50]:
                cve_id = item.get("id", "")
                raw = {
                    "cve_id": cve_id,
                    "title": item.get("id", ""),
                    "description": item.get("summary", ""),
                    "severity": self._map_severity(item.get("cvss", 0)),
                    "publish_date": item.get("Published", item.get("published", "")),
                    "affected_products": "",
                    "fix_recommendation": "",
                    "references": item.get("references", []),
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[DailyCVE] Collection failed: {e}")

        logger.info(f"[DailyCVE] Collected {len(results)} vulnerabilities")
        return results

    @staticmethod
    def _map_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "Critical"
        elif cvss >= 7.0:
            return "High"
        elif cvss >= 4.0:
            return "Medium"
        return "Low"
