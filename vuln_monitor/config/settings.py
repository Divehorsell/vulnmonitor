import os
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        yaml_file="config.yaml",
        extra="ignore",
    )

    app_name: str = "vulnmonitor"
    app_version: str = "0.1.0"
    debug: bool = False

    db_path: str = str(Path(__file__).parent.parent.parent / "data" / "vulnmonitor.db")

    crawl_interval: int = 15
    crawl_timeout: int = 30
    crawl_max_retries: int = 3
    crawl_concurrency: int = 20

    dedup_ttl_days: int = 60

    push_enabled: bool = True
    push_score_threshold: float = 50.0

    tg_bot_token: Optional[str] = None
    tg_chat_id: Optional[str] = None

    dingtalk_webhook: Optional[str] = None
    dingtalk_secret: Optional[str] = None

    wecom_webhook: Optional[str] = None

    feishu_webhook: Optional[str] = None
    feishu_secret: Optional[str] = None

    email_smtp_host: Optional[str] = None
    email_smtp_port: int = 465
    email_smtp_user: Optional[str] = None
    email_smtp_password: Optional[str] = None
    email_from: Optional[str] = None
    email_to: list[str] = Field(default_factory=list)

    github_token: Optional[str] = None

    web_host: str = "127.0.0.1"
    web_port: int = 8080

    log_level: str = "INFO"
    log_dir: str = str(Path(__file__).parent.parent.parent / "data" / "logs")
    log_rotation: str = "10 MB"
    log_retention: str = "30 days"

    encryption_key: Optional[str] = None

    @property
    def data_dir(self) -> Path:
        return Path(self.db_path).parent

    def ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings


settings = load_settings()
