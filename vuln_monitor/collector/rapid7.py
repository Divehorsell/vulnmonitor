import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class Rapid7Collector(BaseCollector):
    name = "Rapid7"
    source_type = "research"
    base_url = "https://www.rapid7.com/db/api/v1"

    def collect(self) -> list[dict]:
        results = []
        try:
            data = self.fetch_json(f"{self.base_url}/vulnerabilities", params={"sort": "recent", "limit": 30})
            vulns = data.get("vulnerabilities", data if isinstance(data, list) else [])
            for item in vulns[:30]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", str(item.get("title", "")), re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else ""

                raw = {
                    "cve_id": cve_id or f"R7-{item.get('id', '')}",
                    "title": item.get("title", ""),
                    "description": item.get("description", ""),
                    "severity": item.get("severity", "High"),
                    "publish_date": item.get("date", item.get("published_at", "")),
                    "affected_products": item.get("affectedSoftware", ""),
                    "fix_recommendation": "",
                    "references": [item.get("url", "")],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[Rapid7] Collection failed: {e}")

        logger.info(f"[Rapid7] Collected {len(results)} advisories")
        return results
