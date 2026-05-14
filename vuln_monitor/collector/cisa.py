from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class CISACollector(BaseCollector):
    name = "CISA_KEV"
    source_type = "disclosure"
    base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def collect(self) -> list[dict]:
        try:
            data = self.fetch_json(self.base_url)
            vulnerabilities = data.get("vulnerabilities", [])
            results = []
            for vuln in vulnerabilities:
                raw = {
                    "cve_id": vuln.get("cveID", ""),
                    "title": vuln.get("vulnerabilityName", ""),
                    "description": vuln.get("shortDescription", ""),
                    "severity": "High",
                    "publish_date": vuln.get("dateAdded", ""),
                    "affected_products": vuln.get("product", ""),
                    "fix_recommendation": vuln.get("required_action", ""),
                    "references": [vuln.get("notes", "")] if vuln.get("notes") else [],
                    "poc_available": False,
                    "kev_marked": True,
                }
                results.append(self.normalize(raw))
            logger.info(f"[CISA_KEV] Collected {len(results)} vulnerabilities")
            return results
        except Exception as e:
            logger.error(f"[CISA_KEV] Collection failed: {e}")
            return []
