import re
from datetime import datetime

from loguru import logger

from vuln_monitor.collector.base import BaseCollector
from vuln_monitor.config.settings import settings


class GitHubPoCCollector(BaseCollector):
    name = "GitHub_PoC"
    source_type = "exploit"
    base_url = "https://api.github.com"

    def collect(self) -> list[dict]:
        if not settings.github_token:
            logger.warning("[GitHub_PoC] No GitHub token configured, skipping")
            return []

        results = []
        search_queries = [
            "CVE-2025 RCE PoC",
            "CVE-2025 exploit",
            "CVE-2026 RCE PoC",
            "CVE-2026 exploit",
        ]

        for query in search_queries:
            try:
                data = self.fetch_json(
                    f"{self.base_url}/search/repositories",
                    params={"q": query, "sort": "updated", "order": "desc", "per_page": 30},
                )
                for repo in data.get("items", []):
                    cve_match = re.search(r"CVE-\d{4}-\d{4,}", repo.get("name", "") + " " + repo.get("description", ""), re.IGNORECASE)
                    cve_id = cve_match.group(0).upper() if cve_match else ""

                    raw = {
                        "cve_id": cve_id or f"GH-{repo['id']}",
                        "title": repo.get("name", ""),
                        "description": repo.get("description", ""),
                        "severity": "High",
                        "publish_date": repo.get("updated_at", "")[:10],
                        "affected_products": "",
                        "fix_recommendation": "",
                        "references": [repo.get("html_url", "")],
                        "poc_available": True,
                        "kev_marked": False,
                    }
                    results.append(self.normalize(raw))
            except Exception as e:
                logger.error(f"[GitHub_PoC] Search '{query}' failed: {e}")

        logger.info(f"[GitHub_PoC] Collected {len(results)} repositories")
        return results
