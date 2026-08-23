"""Shared HTTP client: rate limiting, retries, consistent UA."""
from __future__ import annotations

import time

import requests
import requests.adapters
import urllib3

DEFAULT_UA = "ART-Scanner/1.0 (authorized security assessment)"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HttpClient:
    def __init__(self, timeout: float = 10.0, rate_limit: float = 0.0,
                 user_agent: str = DEFAULT_UA, verify: bool = False, max_retries: int = 2):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        self.timeout = timeout
        self.rate_limit = rate_limit  # min seconds between requests
        self.max_retries = max_retries
        self.verify = verify
        self._last_request_ts = 0.0
        adapter = requests.adapters.HTTPAdapter(max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _throttle(self) -> None:
        if self.rate_limit > 0:
            wait = self._last_request_ts + self.rate_limit - time.time()
            if wait > 0:
                time.sleep(wait)
        self._last_request_ts = time.time()

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                return self.session.request(method, url, **kwargs)
            except requests.RequestException as e:
                last_exc = e
                time.sleep(0.5 * (attempt + 1))
        raise last_exc  # type: ignore[misc]

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)
