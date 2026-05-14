import hashlib
import hmac
import base64
import time

import httpx
from loguru import logger

from vuln_monitor.config.settings import settings
from vuln_monitor.notifier.base import BaseNotifier
from vuln_monitor.storage.database import DatabaseManager


class FeishuNotifier(BaseNotifier):
    channel = "feishu"

    def __init__(self, db: DatabaseManager):
        super().__init__(db)
        self.webhook = settings.feishu_webhook
        self.secret = settings.feishu_secret

    def is_configured(self) -> bool:
        return bool(self.webhook)

    def _build_url(self) -> str:
        url = self.webhook
        if self.secret:
            timestamp = str(round(time.time()))
            string_to_sign = f"{timestamp}\n{self.secret}"
            hmac_code = hmac.new(
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
            sign = base64.b64encode(hmac_code).decode("utf-8")
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}timestamp={timestamp}&sign={sign}"
        return url

    def _send(self, message: str, vuln: dict) -> bool:
        url = self._build_url()
        severity = vuln.get("severity", "High")

        payload = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {
                        "tag": "plain_text",
                        "content": f"🚨 漏洞告警 - {vuln.get('cve_id', 'N/A')} [{severity}]",
                    },
                    "template": self._severity_color(severity),
                },
                "elements": self._build_elements(vuln),
            },
        }

        with httpx.Client(timeout=30) as client:
            response = client.post(url, json=payload)
            result = response.json()
            if result.get("code") == 0 or result.get("StatusCode") == 0:
                logger.info(f"[Feishu] Pushed: {vuln.get('cve_id', 'N/A')}")
                return True
            else:
                logger.error(f"[Feishu] API error: {result.get('msg', 'unknown')}")
                return False

    def _severity_color(self, severity: str) -> str:
        return {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "green"}.get(severity, "blue")

    def _build_elements(self, vuln: dict) -> list:
        elements = []
        fields = [
            ("CVE", vuln.get("cve_id", "N/A")),
            ("标题", vuln.get("title", "N/A")),
            ("严重等级", vuln.get("severity", "N/A")),
            ("来源", vuln.get("source", "N/A")),
            ("评分", str(vuln.get("quality_score", 0))),
        ]
        if vuln.get("description"):
            fields.append(("描述", vuln["description"][:300]))
        if vuln.get("affected_products"):
            fields.append(("受影响产品", vuln["affected_products"]))
        if vuln.get("poc_available"):
            fields.append(("PoC", "✅ 已公开"))
        if vuln.get("kev_marked"):
            fields.append(("KEV", "✅ CISA已知被利用"))

        for label, value in fields:
            elements.append({
                "tag": "div",
                "fields": [
                    {
                        "is_short": True,
                        "text": {"tag": "lark_md", "content": f"**{label}:** {value}"},
                    }
                ],
            })

        return elements
