import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from loguru import logger

from vuln_monitor.config.settings import settings
from vuln_monitor.notifier.base import BaseNotifier
from vuln_monitor.storage.database import DatabaseManager


class EmailNotifier(BaseNotifier):
    channel = "email"

    def __init__(self, db: DatabaseManager):
        super().__init__(db)
        self.smtp_host = settings.email_smtp_host
        self.smtp_port = settings.email_smtp_port
        self.smtp_user = settings.email_smtp_user
        self.smtp_password = settings.email_smtp_password
        self.from_addr = settings.email_from or settings.email_smtp_user
        self.to_addrs = settings.email_to

    def is_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.to_addrs)

    def _send(self, message: str, vuln: dict) -> bool:
        cve_id = vuln.get("cve_id", "N/A")
        severity = vuln.get("severity", "High")
        subject = f"🚨 漏洞告警 - {cve_id} [{severity}]"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        html_content = self._to_html(vuln)
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        try:
            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                server.starttls()

            if self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)

            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            server.quit()
            logger.info(f"[Email] Pushed: {cve_id}")
            return True
        except Exception as e:
            logger.error(f"[Email] Push failed: {e}")
            return False

    def _to_html(self, vuln: dict) -> str:
        severity_colors = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#ca8a04",
            "Low": "#16a34a",
        }
        color = severity_colors.get(vuln.get("severity", ""), "#6b7280")

        rows = [
            ("CVE", vuln.get("cve_id", "N/A")),
            ("标题", vuln.get("title", "N/A")),
            ("严重等级", vuln.get("severity", "N/A")),
            ("来源", vuln.get("source", "N/A")),
            ("评分", vuln.get("quality_score", 0)),
        ]
        if vuln.get("description"):
            rows.append(("描述", vuln["description"][:500]))
        if vuln.get("affected_products"):
            rows.append(("受影响产品", vuln["affected_products"]))
        if vuln.get("poc_available"):
            rows.append(("PoC", "✅ 已公开"))
        if vuln.get("kev_marked"):
            rows.append(("KEV", "✅ CISA已知被利用"))

        table_rows = ""
        for label, value in rows:
            table_rows += f'<tr><td style="padding:8px;border:1px solid #e5e7eb;font-weight:bold;">{label}</td><td style="padding:8px;border:1px solid #e5e7eb;">{value}</td></tr>'

        return f"""
        <html><body>
        <div style="max-width:600px;margin:0 auto;font-family:sans-serif;">
            <div style="background:{color};color:white;padding:16px;border-radius:8px 8px 0 0;">
                <h2 style="margin:0;">🚨 漏洞告警</h2>
            </div>
            <table style="width:100%;border-collapse:collapse;">
                {table_rows}
            </table>
        </div>
        </body></html>
        """
