import httpx
from loguru import logger

from vuln_monitor.config.settings import settings
from vuln_monitor.notifier.base import BaseNotifier
from vuln_monitor.storage.database import DatabaseManager


class TelegramNotifier(BaseNotifier):
    channel = "telegram"

    def __init__(self, db: DatabaseManager):
        super().__init__(db)
        self.bot_token = settings.tg_bot_token
        self.chat_id = settings.tg_chat_id
        self.api_base = "https://api.telegram.org"

    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _send(self, message: str, vuln: dict) -> bool:
        url = f"{self.api_base}/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        with httpx.Client(timeout=30) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            result = response.json()

            if result.get("ok"):
                logger.info(f"[Telegram] Pushed: {vuln.get('cve_id', 'N/A')}")
                return True
            else:
                logger.error(f"[Telegram] API error: {result.get('description', 'unknown')}")
                return False
