import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class Horizon3Collector(BaseCollector):
    name = "Horizon3"
    source_type = "research"
    base_url = "https://horizon3.ai"

    def collect(self) -> list[dict]:
        results = []
        try:
            response = self.fetch(f"{self.base_url}/api/v1/advisories")
            data = response.json()
            advisories = data if isinstance(data, list) else data.get("advisories", data.get("data", []))
            for item in advisories[:20]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", str(item.get("title", "")), re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else ""

                raw = {
                    "cve_id": cve_id or f"H3-{item.get('id', '')}",
                    "title": item.get("title", ""),
                    "description": item.get("summary", ""),
                    "severity": "Critical",
                    "publish_date": item.get("date", ""),
                    "affected_products": item.get("product", ""),
                    "fix_recommendation": item.get("solution", ""),
                    "references": [item.get("url", "")],
                    "poc_available": True,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[Horizon3] Collection failed: {e}")

        logger.info(f"[Horizon3] Collected {len(results)} advisories")
        return results
