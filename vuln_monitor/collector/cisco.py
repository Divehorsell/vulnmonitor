import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class CiscoCollector(BaseCollector):
    name = "Cisco_PSIRT"
    source_type = "psirt"
    base_url = "https://api.cisco.com/security/advisories"

    def collect(self) -> list[dict]:
        results = []
        try:
            response = self.fetch(f"{self.base_url}/all")
            data = response.json()
            advisories = data.get("advisories", data if isinstance(data, list) else [])
            for item in advisories[:30]:
                cves = item.get("cves", [])
                cve_id = cves[0] if cves else ""

                raw = {
                    "cve_id": cve_id or f"CISCO-SA-{item.get('advisoryId', '')}",
                    "title": item.get("advisoryTitle", ""),
                    "description": item.get("summary", ""),
                    "severity": item.get("sir", "High"),
                    "publish_date": item.get("firstPublished", ""),
                    "affected_products": ", ".join(item.get("productNames", [])),
                    "fix_recommendation": "",
                    "references": [item.get("advisoryUrl", "")],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[Cisco_PSIRT] Collection failed: {e}")

        logger.info(f"[Cisco_PSIRT] Collected {len(results)} advisories")
        return results
