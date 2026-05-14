from abc import ABC, abstractmethod
from typing import Optional

from loguru import logger

from vuln_monitor.storage.database import DatabaseManager


class BaseNotifier(ABC):
    channel: str = "base"

    def __init__(self, db: DatabaseManager):
        self.db = db

    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def _send(self, message: str, vuln: dict) -> bool:
        raise NotImplementedError

    def notify(self, vuln: dict) -> bool:
        if not self.is_configured():
            return False

        message = self.format_message(vuln)
        try:
            success = self._send(message, vuln)
            self._log_push(vuln, success)
            return success
        except Exception as e:
            logger.error(f"[{self.channel}] Push failed: {e}")
            self._log_push(vuln, False, str(e))
            return False

    def format_message(self, vuln: dict, detailed: bool = True) -> str:
        cve_id = vuln.get("cve_id", "N/A")
        title = vuln.get("title", "N/A")
        severity = vuln.get("severity", "N/A")
        source = vuln.get("source", "N/A")
        score = vuln.get("quality_score", 0)

        severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        emoji = severity_emoji.get(severity, "⚪")

        if not detailed:
            return f"{emoji} [{severity}] {cve_id} - {title} (来源: {source}, 评分: {score})"

        parts = [
            f"{emoji} <b>漏洞告警</b>",
            f"<b>CVE:</b> {cve_id}",
            f"<b>标题:</b> {title}",
            f"<b>严重等级:</b> {severity}",
            f"<b>来源:</b> {source}",
            f"<b>评分:</b> {score}",
        ]

        if vuln.get("description"):
            desc = vuln["description"]
            if len(desc) > 500:
                desc = desc[:500] + "..."
            parts.append(f"<b>描述:</b> {desc}")

        if vuln.get("affected_products"):
            parts.append(f"<b>受影响产品:</b> {vuln['affected_products']}")

        if vuln.get("fix_recommendation"):
            parts.append(f"<b>修复建议:</b> {vuln['fix_recommendation']}")

        if vuln.get("poc_available"):
            parts.append("<b>PoC:</b> ✅ 已公开")

        if vuln.get("kev_marked"):
            parts.append("<b>KEV:</b> ✅ CISA已知被利用")

        if vuln.get("references"):
            refs = vuln["references"]
            if isinstance(refs, str):
                import json
                try:
                    refs = json.loads(refs)
                except (json.JSONDecodeError, TypeError):
                    refs = [refs]
            for i, ref in enumerate(refs[:3], 1):
                parts.append(f"<b>参考链接{i}:</b> {ref}")

        return "\n".join(parts)

    def _log_push(self, vuln: dict, success: bool, error: str = None):
        vuln_id = vuln.get("id", 0)
        message_preview = f"{vuln.get('cve_id', '')} - {vuln.get('title', '')}"
        self.db.log_push(
            vuln_id=vuln_id,
            channel=self.channel,
            message_preview=message_preview,
            status="success" if success else "failed",
            error_message=error,
        )
