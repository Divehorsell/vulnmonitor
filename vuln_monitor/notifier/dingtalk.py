import hashlib
import hmac
import base64
import time
import urllib.parse

import httpx
from loguru import logger

from vuln_monitor.config.settings import settings
from vuln_monitor.notifier.base import BaseNotifier
from vuln_monitor.storage.database import DatabaseManager


class DingTalkNotifier(BaseNotifier):
    channel = "dingtalk"

    def __init__(self, db: DatabaseManager):
        super().__init__(db)
        self.webhook = settings.dingtalk_webhook
        self.secret = settings.dingtalk_secret

    def is_configured(self) -> bool:
        return bool(self.webhook)

    def _build_url(self) -> str:
        url = self.webhook
        if self.secret:
            timestamp = str(round(time.time() * 1000))
            string_to_sign = f"{timestamp}\n{self.secret}"
            hmac_code = hmac.new(
                self.secret.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            url = f"{url}&timestamp={timestamp}&sign={sign}"
        return url

    def _send(self, message: str, vuln: dict) -> bool:
        url = self._build_url()
        severity = vuln.get("severity", "High")
        title = f"🚨 漏洞告警 - {vuln.get('cve_id', 'N/A')} [{severity}]"

        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": self._to_markdown(vuln),
            },
        }

        with httpx.Client(timeout=30) as client:
            response = client.post(url, json=payload)
            result = response.json()
            if result.get("errcode") == 0:
                logger.info(f"[DingTalk] Pushed: {vuln.get('cve_id', 'N/A')}")
                return True
            else:
                logger.error(f"[DingTalk] API error: {result.get('errmsg', 'unknown')}")
                return False

    def _to_markdown(self, vuln: dict) -> str:
        parts = [
            f"### 🚨 漏洞告警",
            f"- **CVE:** {vuln.get('cve_id', 'N/A')}",
            f"- **标题:** {vuln.get('title', 'N/A')}",
            f"- **严重等级:** {vuln.get('severity', 'N/A')}",
            f"- **来源:** {vuln.get('source', 'N/A')}",
            f"- **评分:** {vuln.get('quality_score', 0)}",
        ]
        if vuln.get("description"):
            desc = vuln["description"][:300]
            parts.append(f"- **描述:** {desc}")
        if vuln.get("affected_products"):
            parts.append(f"- **受影响产品:** {vuln['affected_products']}")
        if vuln.get("poc_available"):
            parts.append("- **PoC:** ✅ 已公开")
        if vuln.get("kev_marked"):
            parts.append("- **KEV:** ✅ CISA已知被利用")
        return "\n".join(parts)
