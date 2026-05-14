from abc import ABC, abstractmethod
from typing import Optional

import httpx
from loguru import logger

from vuln_monitor.config.settings import settings
from vuln_monitor.utils.retry import retry


class BaseCollector(ABC):
    name: str = "base"
    source_type: str = "unknown"
    base_url: str = ""

    def __init__(self):
        self.timeout = settings.crawl_timeout
        self.max_retries = settings.crawl_max_retries
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers=self._get_headers(),
            )
        return self._client

    def _get_headers(self) -> dict:
        headers = {
            "User-Agent": "VulnMonitor/0.1.0 (Security Vulnerability Intelligence Scanner)",
            "Accept": "application/json, text/html, */*",
        }
        if settings.github_token and "github" in self.base_url.lower():
            headers["Authorization"] = f"token {settings.github_token}"
        return headers

    @retry(max_retries=3, base_delay=1.0, exceptions=(httpx.HTTPError, httpx.TimeoutException))
    def fetch(self, url: str, params: dict = None) -> httpx.Response:
        logger.debug(f"[{self.name}] Fetching: {url}")
        response = self.client.get(url, params=params)
        response.raise_for_status()
        return response

    @retry(max_retries=3, base_delay=1.0, exceptions=(httpx.HTTPError, httpx.TimeoutException))
    def fetch_json(self, url: str, params: dict = None) -> dict | list:
        response = self.fetch(url, params)
        return response.json()

    @retry(max_retries=3, base_delay=1.0, exceptions=(httpx.HTTPError, httpx.TimeoutException))
    async def async_fetch(self, url: str, params: dict = None) -> httpx.Response:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=self._get_headers(),
        ) as client:
            logger.debug(f"[{self.name}] Async fetching: {url}")
            response = await client.get(url, params=params)
            response.raise_for_status()
            return response

    @abstractmethod
    def collect(self) -> list[dict]:
        raise NotImplementedError

    def normalize(self, raw: dict) -> dict:
        return {
            "cve_id": raw.get("cve_id", ""),
            "title": raw.get("title", ""),
            "description": raw.get("description"),
            "severity": raw.get("severity"),
            "source": self.name,
            "publish_date": raw.get("publish_date", ""),
            "affected_products": raw.get("affected_products"),
            "fix_recommendation": raw.get("fix_recommendation"),
            "references": raw.get("references", []),
            "poc_available": raw.get("poc_available", False),
            "kev_marked": raw.get("kev_marked", False),
            "quality_score": raw.get("quality_score", 0.0),
        }

    def close(self):
        if self._client and not self._client.is_closed:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
