import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector


class MicrosoftMSRCCollector(BaseCollector):
    name = "Microsoft_MSRC"
    source_type = "psirt"
    base_url = "https://api.msrc.microsoft.com/cvrf/v2.0"

    def collect(self) -> list[dict]:
        results = []
        try:
            response = self.fetch(f"{self.base_url}/cvrf")
            data = response.json()
            for vuln in data.get("Vulnerability", [])[:30]:
                cve_id = vuln.get("CVE", "")
                title = vuln.get("Title", {}).get("Value", cve_id)

                severities = []
                for score_set in vuln.get("CVSSScoreSets", []):
                    base_score = score_set.get("BaseScore", 0)
                    if base_score >= 9.0:
                        severities.append("Critical")
                    elif base_score >= 7.0:
                        severities.append("High")
                    elif base_score >= 4.0:
                        severities.append("Medium")
                    else:
                        severities.append("Low")

                raw = {
                    "cve_id": cve_id,
                    "title": title,
                    "description": vuln.get("Notes", [{}])[0].get("Value", "") if vuln.get("Notes") else "",
                    "severity": severities[0] if severities else "High",
                    "publish_date": vuln.get("ReleaseDate", ""),
                    "affected_products": ", ".join(
                        p.get("ProductID", "") for p in vuln.get("ProductStatuses", [])
                    ),
                    "fix_recommendation": "",
                    "references": [r.get("URL", "") for r in vuln.get("References", [])],
                    "poc_available": False,
                    "kev_marked": False,
                }
                results.append(self.normalize(raw))
        except Exception as e:
            logger.error(f"[Microsoft_MSRC] Collection failed: {e}")

        logger.info(f"[Microsoft_MSRC] Collected {len(results)} advisories")
        return results
