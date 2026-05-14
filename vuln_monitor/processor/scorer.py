from loguru import logger


SOURCE_AUTHORITY = {
    "CISA_KEV": 100,
    "Microsoft_MSRC": 95,
    "Cisco_PSIRT": 90,
    "Fortinet_PSIRT": 90,
    "PaloAlto_PSIRT": 90,
    "ZDI": 85,
    "watchTowr": 80,
    "Horizon3": 80,
    "Rapid7": 75,
    "QiAnXin": 75,
    "ThreatBook": 70,
    "Chaitin_Rivers": 70,
    "OSCS": 70,
    "DailyCVE": 60,
    "Sploitus": 55,
    "GitHub_PoC": 50,
}

SEVERITY_SCORES = {
    "Critical": 40,
    "High": 30,
    "Medium": 15,
    "Low": 5,
}


class Scorer:
    def calculate(self, vuln: dict) -> float:
        score = 0.0

        score += self._completeness_score(vuln)
        score += self._authority_score(vuln.get("source", ""))
        score += self._severity_score(vuln.get("severity", ""))
        score += self._kev_bonus(vuln.get("kev_marked", False))
        score += self._poc_bonus(vuln.get("poc_available", False))
        score += self._asset_bonus(vuln)

        return round(min(score, 100.0), 1)

    def _completeness_score(self, vuln: dict) -> float:
        fields = ["cve_id", "title", "description", "severity", "affected_products", "fix_recommendation"]
        filled = sum(1 for f in fields if vuln.get(f))
        return (filled / len(fields)) * 15

    def _authority_score(self, source: str) -> float:
        return SOURCE_AUTHORITY.get(source, 50) * 0.2

    def _severity_score(self, severity: str) -> float:
        return SEVERITY_SCORES.get(severity, 10)

    def _kev_bonus(self, kev_marked: bool) -> float:
        return 20.0 if kev_marked else 0.0

    def _poc_bonus(self, poc_available: bool) -> float:
        return 10.0 if poc_available else 0.0

    def _asset_bonus(self, vuln: dict) -> float:
        matched = vuln.get("matched_assets", [])
        if matched:
            return min(len(matched) * 2, 10.0)
        return 0.0

    def score_vulnerabilities(self, vulnerabilities: list[dict]) -> list[dict]:
        for vuln in vulnerabilities:
            vuln["quality_score"] = self.calculate(vuln)
        logger.info(f"Scored {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
