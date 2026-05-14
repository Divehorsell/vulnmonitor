import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class SploitusCollector(BaseCollector):
    name = "Sploitus"
    source_type = "exploit"
    base_url = "https://sploitus.com"

    def collect(self) -> list[dict]:
        results = []
        try:
            response = self.fetch(f"{self.base_url}/api/search", params={"type": "exploits", "sort": "date"})
            data = response.json()
            for item in data.get("data", [])[:50]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", item.get("title", ""), re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else ""

                raw = {
                    "cve_id": cve_id or f"SPLOITUS-{item.get('id', '')}",
                    "title": item.get("title", ""),
                    "description": item.get("description", ""),
                    "severity": "High",
                    "publish_date": item.get("date", ""),
                    "affected_products": "",
                    "fix_recommendation": "",
                    "references": [item.get("href", "")],
                    "poc_available": True,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[Sploitus] Collection failed: {e}")

        logger.info(f"[Sploitus] Collected {len(results)} exploits")
        return results
