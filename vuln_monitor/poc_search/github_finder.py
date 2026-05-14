import time
from typing import Optional

import httpx
from loguru import logger


class GitHubPoCFinder:
    API_BASE = "https://api.github.com"

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token
        self._client: Optional[httpx.Client] = None
        self._last_request_time = 0.0
        self._min_interval = 2.0

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "VulnMonitor-PoC-Finder",
            }
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"
            self._client = httpx.Client(
                timeout=30,
                follow_redirects=True,
                headers=headers,
            )
        return self._client

    def _rate_limit_wait(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()

    def _handle_rate_limit(self, response: httpx.Response):
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_time = response.headers.get("X-RateLimit-Reset")

        if remaining is not None and int(remaining) <= 1:
            if reset_time:
                wait_seconds = max(int(reset_time) - int(time.time()), 0) + 1
                logger.warning(f"[GitHubPoCFinder] Rate limit approaching, waiting {wait_seconds}s")
                time.sleep(wait_seconds)
            else:
                logger.warning("[GitHubPoCFinder] Rate limit approaching, waiting 60s")
                time.sleep(60)

        if response.status_code == 403:
            if reset_time:
                wait_seconds = max(int(reset_time) - int(time.time()), 0) + 1
                logger.warning(f"[GitHubPoCFinder] Rate limited, waiting {wait_seconds}s")
                time.sleep(wait_seconds)
            else:
                logger.warning("[GitHubPoCFinder] Rate limited, waiting 60s")
                time.sleep(60)
            return True
        return False

    def search(self, cve_id: str) -> list[dict]:
        results = []
        queries = [
            f"{cve_id} PoC",
            f"{cve_id} exploit",
            f"{cve_id} RCE",
        ]

        seen_repos = set()
        for query in queries:
            self._rate_limit_wait()
            try:
                response = self.client.get(
                    f"{self.API_BASE}/search/repositories",
                    params={"q": query, "sort": "stars", "order": "desc", "per_page": 20},
                )

                if self._handle_rate_limit(response):
                    response = self.client.get(
                        f"{self.API_BASE}/search/repositories",
                        params={"q": query, "sort": "stars", "order": "desc", "per_page": 20},
                    )

                response.raise_for_status()
                data = response.json()

                for repo in data.get("items", []):
                    full_name = repo.get("full_name", "")
                    if full_name in seen_repos:
                        continue
                    seen_repos.add(full_name)

                    results.append({
                        "repo_name": full_name,
                        "url": repo.get("html_url", ""),
                        "description": repo.get("description", "") or "",
                        "stars": repo.get("stargazers_count", 0),
                        "updated_at": repo.get("updated_at", ""),
                        "language": repo.get("language", "") or "",
                    })
            except httpx.HTTPError as e:
                logger.error(f"[GitHubPoCFinder] Search '{query}' failed: {e}")

        results.sort(key=lambda x: x["stars"], reverse=True)
        logger.info(f"[GitHubPoCFinder] Found {len(results)} PoC repos for {cve_id}")
        return results

    def search_by_keyword(self, keyword: str) -> list[dict]:
        self._rate_limit_wait()
        results = []

        try:
            response = self.client.get(
                f"{self.API_BASE}/search/repositories",
                params={"q": keyword, "sort": "stars", "order": "desc", "per_page": 30},
            )

            if self._handle_rate_limit(response):
                response = self.client.get(
                    f"{self.API_BASE}/search/repositories",
                    params={"q": keyword, "sort": "stars", "order": "desc", "per_page": 30},
                )

            response.raise_for_status()
            data = response.json()

            for repo in data.get("items", []):
                results.append({
                    "repo_name": repo.get("full_name", ""),
                    "url": repo.get("html_url", ""),
                    "description": repo.get("description", "") or "",
                    "stars": repo.get("stargazers_count", 0),
                    "updated_at": repo.get("updated_at", ""),
                    "language": repo.get("language", "") or "",
                })
        except httpx.HTTPError as e:
            logger.error(f"[GitHubPoCFinder] Keyword search '{keyword}' failed: {e}")

        results.sort(key=lambda x: x["stars"], reverse=True)
        logger.info(f"[GitHubPoCFinder] Found {len(results)} repos for keyword '{keyword}'")
        return results

    def close(self):
        if self._client and not self._client.is_closed:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
