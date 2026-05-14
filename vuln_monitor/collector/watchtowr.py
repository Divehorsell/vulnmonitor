import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class WatchTowrCollector(BaseCollector):
    name = "watchTowr"
    source_type = "disclosure"
    base_url = "https://labs.watchtowr.com"

    def collect(self) -> list[dict]:
        results = []
        try:
            response = self.fetch(f"{self.base_url}/api/v1/advisories")
            data = response.json()
            advisories = data if isinstance(data, list) else data.get("advisories", data.get("data", []))
            for item in advisories[:30]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", str(item.get("title", "")), re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else ""

                raw = {
                    "cve_id": cve_id or f"WT-{item.get('id', '')}",
                    "title": item.get("title", ""),
                    "description": item.get("summary", item.get("description", "")),
                    "severity": "High",
                    "publish_date": item.get("date", item.get("published_at", "")),
                    "affected_products": item.get("product", ""),
                    "fix_recommendation": "",
                    "references": [item.get("url", item.get("link", ""))],
                    "poc_available": bool(item.get("poc", item.get("exploit", False))),
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[watchTowr] Collection failed: {e}")

        logger.info(f"[watchTowr] Collected {len(results)} advisories")
        return results
