from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger

from vuln_monitor.storage.database import DatabaseManager


class MarkdownReporter:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.report_dir = Path(__file__).parent.parent.parent / "data" / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _get_date_range_vulns(self, start_date: datetime, end_date: datetime) -> list[dict]:
        days = (end_date - start_date).days
        return self.db.query_vulnerabilities(days=days, limit=1000)

    def _build_overview(self, vulns: list[dict], start_date: str, end_date: str) -> str:
        total = len(vulns)
        critical = len([v for v in vulns if v.get("severity") == "Critical"])
        high = len([v for v in vulns if v.get("severity") == "High"])
        medium = len([v for v in vulns if v.get("severity") == "Medium"])
        low = len([v for v in vulns if v.get("severity") == "Low"])
        poc = len([v for v in vulns if v.get("poc_available")])
        kev = len([v for v in vulns if v.get("kev_marked")])
        pushed = len([v for v in vulns if v.get("pushed")])

        lines = [
            f"## 概览统计",
            f"",
            f"- **报告周期**: {start_date} ~ {end_date}",
            f"- **漏洞总数**: {total}",
            f"- **严重等级分布**: Critical {critical} | High {high} | Medium {medium} | Low {low}",
            f"- **PoC 已公开**: {poc}",
            f"- **KEV 标记**: {kev}",
            f"- **已推送告警**: {pushed}",
            f"",
        ]
        return "\n".join(lines)

    def _build_critical_high_details(self, vulns: list[dict]) -> str:
        critical_high = [v for v in vulns if v.get("severity") in ("Critical", "High")]
        if not critical_high:
            return "## 严重/高危漏洞详情\n\n无严重或高危漏洞。\n"

        lines = [
            "## 严重/高危漏洞详情",
            "",
            "| CVE ID | 标题 | 严重等级 | 来源 | 评分 | PoC | KEV |",
            "|--------|------|----------|------|------|-----|-----|",
        ]

        for v in critical_high[:50]:
            poc_icon = "✅" if v.get("poc_available") else "❌"
            kev_icon = "✅" if v.get("kev_marked") else "❌"
            title = (v.get("title", "") or "")[:50]
            lines.append(
                f"| {v.get('cve_id', '')} | {title} | {v.get('severity', '')} | "
                f"{v.get('source', '')} | {v.get('quality_score', 0)} | {poc_icon} | {kev_icon} |"
            )

        if len(critical_high) > 50:
            lines.append(f"\n> 仅展示前 50 条，共 {len(critical_high)} 条严重/高危漏洞")

        lines.append("")
        return "\n".join(lines)

    def _build_source_distribution(self, vulns: list[dict]) -> str:
        source_counts: dict[str, int] = {}
        for v in vulns:
            source = v.get("source", "Unknown")
            source_counts[source] = source_counts.get(source, 0) + 1

        if not source_counts:
            return "## 来源分布\n\n无数据。\n"

        lines = [
            "## 来源分布",
            "",
            "| 来源 | 数量 | 占比 |",
            "|------|------|------|",
        ]

        total = len(vulns)
        for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
            pct = f"{count / total * 100:.1f}%"
            lines.append(f"| {source} | {count} | {pct} |")

        lines.append("")
        return "\n".join(lines)

    def _build_trend_analysis(self, vulns: list[dict], days: int) -> str:
        date_counts: dict[str, int] = {}
        severity_date_counts: dict[str, dict[str, int]] = {}

        for v in vulns:
            pub_date = v.get("publish_date", "")
            if pub_date:
                date_str = pub_date[:10]
                date_counts[date_str] = date_counts.get(date_str, 0) + 1
                severity = v.get("severity", "Unknown")
                if date_str not in severity_date_counts:
                    severity_date_counts[date_str] = {}
                severity_date_counts[date_str][severity] = severity_date_counts[date_str].get(severity, 0) + 1

        if not date_counts:
            return "## 趋势分析\n\n无足够数据生成趋势分析。\n"

        lines = [
            "## 趋势分析",
            "",
            "| 日期 | 总数 | Critical | High | Medium | Low |",
            "|------|------|----------|------|--------|-----|",
        ]

        for date_str in sorted(date_counts.keys()):
            sev_counts = severity_date_counts.get(date_str, {})
            lines.append(
                f"| {date_str} | {date_counts[date_str]} | "
                f"{sev_counts.get('Critical', 0)} | {sev_counts.get('High', 0)} | "
                f"{sev_counts.get('Medium', 0)} | {sev_counts.get('Low', 0)} |"
            )

        avg_daily = len(vulns) / max(days, 1)
        max_day = max(date_counts.values()) if date_counts else 0
        lines.append(f"\n- **日均漏洞数**: {avg_daily:.1f}")
        lines.append(f"- **单日最高**: {max_day}")
        lines.append("")
        return "\n".join(lines)

    def _build_remediation_suggestions(self, vulns: list[dict]) -> str:
        kev_vulns = [v for v in vulns if v.get("kev_marked")]
        poc_vulns = [v for v in vulns if v.get("poc_available")]
        critical_vulns = [v for v in vulns if v.get("severity") == "Critical"]

        lines = [
            "## 修复建议",
            "",
        ]

        if kev_vulns:
            lines.append("### 🔴 已知被利用漏洞 (KEV) - 需立即修复")
            for v in kev_vulns[:10]:
                lines.append(f"- **{v.get('cve_id', '')}**: {v.get('title', '')}")
                if v.get("fix_recommendation"):
                    lines.append(f"  - 修复方案: {v['fix_recommendation']}")
            lines.append("")

        if poc_vulns:
            lines.append("### 🟠 PoC 已公开漏洞 - 建议优先修复")
            for v in poc_vulns[:10]:
                lines.append(f"- **{v.get('cve_id', '')}**: {v.get('title', '')}")
                if v.get("fix_recommendation"):
                    lines.append(f"  - 修复方案: {v['fix_recommendation']}")
            lines.append("")

        if critical_vulns:
            lines.append("### 🔴 严重漏洞 - 建议尽快修复")
            for v in critical_vulns[:10]:
                lines.append(f"- **{v.get('cve_id', '')}**: {v.get('title', '')}")
                if v.get("fix_recommendation"):
                    lines.append(f"  - 修复方案: {v['fix_recommendation']}")
            lines.append("")

        if not kev_vulns and not poc_vulns and not critical_vulns:
            lines.append("当前周期内无紧急需要修复的漏洞。")
            lines.append("")

        return "\n".join(lines)

    def _generate_report(self, vulns: list[dict], start_date: str, end_date: str, title: str, days: int) -> str:
        sections = [
            f"# {title}",
            "",
            f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            self._build_overview(vulns, start_date, end_date),
            self._build_critical_high_details(vulns),
            self._build_source_distribution(vulns),
            self._build_trend_analysis(vulns, days),
            self._build_remediation_suggestions(vulns),
        ]
        return "\n".join(sections)

    def _save_report(self, content: str, filename: str) -> Path:
        filepath = self.report_dir / filename
        filepath.write_text(content, encoding="utf-8")
        logger.info(f"[MarkdownReporter] Report saved to {filepath}")
        return filepath

    def generate_weekly_report(self) -> str:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        vulns = self._get_date_range_vulns(start_date, end_date)

        content = self._generate_report(
            vulns=vulns,
            start_date=start_date.strftime("%Y-%m-%d"),
            end_date=end_date.strftime("%Y-%m-%d"),
            title="漏洞情报周报",
            days=7,
        )

        filename = f"weekly_report_{end_date.strftime('%Y%m%d')}.md"
        self._save_report(content, filename)
        return content

    def generate_monthly_report(self) -> str:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        vulns = self._get_date_range_vulns(start_date, end_date)

        content = self._generate_report(
            vulns=vulns,
            start_date=start_date.strftime("%Y-%m-%d"),
            end_date=end_date.strftime("%Y-%m-%d"),
            title="漏洞情报月报",
            days=30,
        )

        filename = f"monthly_report_{end_date.strftime('%Y%m')}.md"
        self._save_report(content, filename)
        return content

    def generate_custom_report(self, days: int) -> str:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        vulns = self._get_date_range_vulns(start_date, end_date)

        content = self._generate_report(
            vulns=vulns,
            start_date=start_date.strftime("%Y-%m-%d"),
            end_date=end_date.strftime("%Y-%m-%d"),
            title=f"漏洞情报报告 (近 {days} 天)",
            days=days,
        )

        filename = f"custom_report_{days}d_{end_date.strftime('%Y%m%d')}.md"
        self._save_report(content, filename)
        return content
