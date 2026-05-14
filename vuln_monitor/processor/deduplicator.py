from loguru import logger

from vuln_monitor.storage.database import DatabaseManager


class Deduplicator:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def is_duplicate(self, vuln: dict) -> bool:
        cve_id = vuln.get("cve_id", "")
        if not cve_id:
            return False
        return self.db.vulnerability_exists(cve_id)

    def deduplicate(self, vulnerabilities: list[dict]) -> list[dict]:
        unique = []
        seen_cve_ids = set()
        duplicate_count = 0

        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "")
            if not cve_id:
                unique.append(vuln)
                continue

            if cve_id in seen_cve_ids:
                duplicate_count += 1
                continue

            if self.db.vulnerability_exists(cve_id):
                duplicate_count += 1
                self._update_if_needed(vuln)
                continue

            seen_cve_ids.add(cve_id)
            unique.append(vuln)

        logger.info(f"Deduplication: {len(vulnerabilities)} -> {len(unique)} ({duplicate_count} duplicates removed)")
        return unique

    def _update_if_needed(self, vuln: dict):
        cve_id = vuln.get("cve_id", "")
        existing = self.db.get_vulnerability(cve_id)
        if not existing:
            return

        updates = {}
        if vuln.get("poc_available") and not existing.get("poc_available"):
            updates["poc_available"] = True
        if vuln.get("kev_marked") and not existing.get("kev_marked"):
            updates["kev_marked"] = True
        if vuln.get("quality_score", 0) > existing.get("quality_score", 0):
            updates["quality_score"] = vuln["quality_score"]
        if vuln.get("description") and not existing.get("description"):
            updates["description"] = vuln["description"]

        if updates:
            self.db.update_vulnerability(cve_id, updates)
            logger.debug(f"Updated existing vulnerability: {cve_id} with {list(updates.keys())}")
