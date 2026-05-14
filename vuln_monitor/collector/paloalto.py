import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class PaloAltoCollector(BaseCollector):
    name = "PaloAlto_PSIRT"
    source_type = "psirt"
    base_url = "https://security.paloaltonetworks.com/api/v1"

    def collect(self) -> list[dict]:
        results = []
        try:
            data = self.fetch_json(f"{self.base_url}/advisories")
            advisories = data if isinstance(data, list) else data.get("advisories", data.get("data", []))
            for item in advisories[:30]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", str(item.get("cve", item.get("title", ""))), re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else ""

                raw = {
                    "cve_id": cve_id or f"PAN-SA-{item.get('id', '')}",
                    "title": item.get("title", item.get("name", "")),
                    "description": item.get("description", item.get("summary", "")),
                    "severity": item.get("severity", "High"),
                    "publish_date": item.get("date", item.get("publishDate", "")),
                    "affected_products": item.get("affectedProducts", item.get("product", "")),
                    "fix_recommendation": item.get("solution", ""),
                    "references": [item.get("url", "")],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[PaloAlto_PSIRT] Collection failed: {e}")

        logger.info(f"[PaloAlto_PSIRT] Collected {len(results)} advisories")
        return results
