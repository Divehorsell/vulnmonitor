import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class ZDICollector(BaseCollector):
    name = "ZDI"
    source_type = "disclosure"
    base_url = "https://www.zerodayinitiative.com"

    def collect(self) -> list[dict]:
        results = []
        try:
            response = self.fetch(f"{self.base_url}/advisories/published/")
            advisories = re.findall(
                r'<a[^>]*href="(/advisories/ZDI-\d{2}-\d{3,}/)"[^>]*>([^<]+)</a>',
                response.text,
            )
            for href, title in advisories[:30]:
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", title, re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else ""

                raw = {
                    "cve_id": cve_id or href.strip("/").split("/")[-1],
                    "title": title.strip(),
                    "description": "",
                    "severity": "High",
                    "publish_date": datetime.now().strftime("%Y-%m-%d"),
                    "affected_products": "",
                    "fix_recommendation": "",
                    "references": [f"{self.base_url}{href}"],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[ZDI] Collection failed: {e}")

        logger.info(f"[ZDI] Collected {len(results)} advisories")
        return results
