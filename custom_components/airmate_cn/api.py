"""Generic API management."""

import asyncio
from collections import defaultdict
from dataclasses import dataclass
import datetime

# from hashlib import md5
import logging
import time

# import math
from typing import collections

# from uuid import uuid4
import httpx
import jwt

from .api_utils import (
    RESPONSE_STORE,
    APIError,
    AuthError,
    anonymize_response,
    handle_httpstatuserror,
)
from .const import (
    DEFAULT_API_HOST,
    DEFAULT_MSG_API_HOST,
    EXPIRES_AT_OFFSET,
    HTTPX_TIMEOUT,
    X_USER_AGENT,
)

_LOGGER = logging.getLogger(__name__)

_LOGGER.info("DEFAULT_API_HOST: %s", DEFAULT_API_HOST)


class APIAuth(httpx.Auth):
    """API authentication."""

    requires_response_body = True

    def __init__(
        self,
        username: str,
        password: str,
        access_token: str | None = None,
        refresh_token: str | None = None,
        refresh_url: str | None = None,
    ) -> None:
        """Initialize the auth."""

        self._lock: asyncio.Lock | None = None
        self.expires_at: datetime.datetime | None = None
        self.refresh_url = refresh_url or "/auth/refresh"
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.username = username
        self.password = password

    @property
    def login_lock(self) -> asyncio.Lock:
        """Make sure that there is a lock in the current event loop."""
        if not self._lock:
            self._lock = asyncio.Lock()
        return self._lock

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> collections.abc.Generator[httpx.Request, httpx.Response, None]:
        """Sync auth flow."""
        raise RuntimeError("Cannot use a async authentication class with httpx.Client")

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> collections.abc.AsyncGenerator[httpx.Request, httpx.Response]:
        """Async auth flow."""
        # Get an access token on first call
        async with self.login_lock:
            if not self.access_token:
                await self.login()

        request.headers["Authorization"] = self._build_auth_header()

        # Try getting a response
        response: httpx.Response = yield request

        # return directly if first response was successful
        if response.is_success:
            return

        await response.aread()

        # Handle 401 Unauthorized and try getting a new token
        if response.status_code == 401:
            async with self.login_lock:
                _LOGGER.debug("Received unauthorized response, refreshing token")
                await self.login()

            request.headers["Authorization"] = f"Bearer {self.access_token}"
            response = yield request

        # Raise if request still was not successful
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as ex:
            await handle_httpstatuserror(ex, module="API", log_handler=_LOGGER)

    def _build_auth_header(self):
        """Build the auth header."""
        return f"Bearer {self.access_token}"

    async def login(self) -> None:
        """Get a valid OAuth token."""
        token_data = None

        if self.refresh_token:
            try:
                token_data = await self._refresh_token()
            except APIError as ex:
                _LOGGER.error("Failed to refresh token: %s", ex)

                # Reset token on error
                self.refresh_token = None
                self.access_token = None

        if not token_data:
            token_data = await self._login()

        token_data["expires_at"] = token_data["expires_at"] - EXPIRES_AT_OFFSET

        self.refresh_token = token_data["refresh_token"]
        self.access_token = token_data["access_token"]
        self.expires_at = token_data["expires_at"]

    async def _refresh_token(self) -> dict:
        """Refresh the OAuth token."""
        async with API() as api:
            _LOGGER.debug("Refreshing token")

            current_utc_time = datetime.datetime.now(tz=datetime.UTC)

            # Get token
            response = await api.post(
                "/auth/refresh",
                headers={},
                json={
                    "refresh_token": self.refresh_token,
                },
            )
            response_json = response.json()["data"]

            expiration_time = int(response_json["expires_in"])
            expires_at = current_utc_time + datetime.timedelta(seconds=expiration_time)

        return {
            "refresh_token": response_json["refresh_token"],
            "access_token": response_json["access_token"],
            "expires_at": expires_at,
        }

    async def _login(self) -> dict:
        """Get a valid OAuth token."""
        async with API() as api:
            _LOGGER.debug("Authenticating")

            # Get token
            response = await api.post(
                "/auth/login",
                headers={},
                json={
                    "username": self.username,
                    "password": self.password,
                },
            )
            response_json = response.json()["data"]

            decoded_token = jwt.decode(
                response_json["access_token"],
                algorithms=["HS256"],
                options={"verify_signature": False},
            )
            expires_at = (
                datetime.datetime.fromtimestamp(decoded_token["exp"], tz=datetime.UTC),
            )

        return {
            "refresh_token": response_json["refresh_token"],
            "access_token": response_json["access_token"],
            "expires_at": expires_at,
        }


class API(httpx.AsyncClient):
    """Async HTTP API based on `httpx.AsyncClient`."""

    def __init__(
        self,
        msg_base_url: str | None = DEFAULT_MSG_API_HOST,
        enable_log_responses: bool = False,
        ssl_verify_pem: str | None = None,
        all_proxy_url: str | None = None,
        *args,
        **kwargs,
    ) -> None:
        """Initialize the API."""

        self.msg_base_url = msg_base_url
        self.enable_log_responses = enable_log_responses
        self.ssl_verify_pem = ssl_verify_pem
        self.all_proxy_url = all_proxy_url

        # Proxy config
        if self.all_proxy_url:
            kwargs["proxies"] = {
                "http://": self.all_proxy_url,
                "https://": self.all_proxy_url,
            }

        # SSL verify
        if self.ssl_verify_pem:
            kwargs["verify"] = self.ssl_verify_pem

        # Timeout conf
        kwargs["timeout"] = kwargs.get("timeout") or HTTPX_TIMEOUT

        # Set default values
        kwargs["base_url"] = kwargs.get("base_url") or DEFAULT_API_HOST
        kwargs["headers"] = self.generate_header(kwargs.get("headers"), kwargs)

        # Register event hooks
        kwargs["event_hooks"] = defaultdict(list, **kwargs.get("event_hooks", {}))

        # Event hook for logging content
        async def log_response(response: httpx.Response):
            await response.aread()
            RESPONSE_STORE.append(anonymize_response(response))

        if self.enable_log_responses:
            kwargs["event_hooks"]["response"].append(log_response)

        # Event hook which calls raise_for_status on all requests
        async def raise_for_status_event_handler(response: httpx.Response):
            """Event handler that automatically raises HTTPStatusErrors when attached.

            Will only raise on 4xx/5xx errors but not 401/429 which are handled `self.auth`.
            """
            if response.is_error and response.status_code not in [401, 429]:
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as ex:
                    await handle_httpstatuserror(ex, log_handler=_LOGGER)

            # WorthCloud iOT API
            await response.aread()
            json_data = response.json()
            json_code = int(json_data["code"]) or 200
            if json_code != 200:
                if json_code == 401:
                    # Reset token_id on Unauthorized
                    if self.auth:
                        self.auth.access_token = None

                    raise AuthError(
                        response=response, request=None, message="Unauthorized"
                    )

                raise APIError(
                    response=response, request=None, message=json_data["desc"]
                )

        kwargs["event_hooks"]["response"].append(raise_for_status_event_handler)

        super().__init__(*args, **kwargs)

    def generate_header(self, data: dict | None, all_data: dict) -> dict[str, str]:
        """Generate a header for HTTP requests to the server."""

        headers = {
            "user-agent": X_USER_AGENT,
            "ts": str(int(datetime.datetime.now().timestamp())),
            # "sn": "2bcc8819e83ad16e39bc0be03736c9d9",
            "app_key": "da88885bc39740e2952f01d2a884ed98",
            "app_id": "30002",
            # "appid": "30002",
        }

        if data:
            headers.update(data)

        return headers

    async def get_device_list(self) -> dict:
        """Get device list."""
        return await self.post(
            self.msg_base_url + "/message_center/api/v1/app/shadow/devices",
            json={
                "list": [
                    {
                        "device_id": "9dbfd5e1fc9b413cbf70bb531b972d41",
                        "product_key": "0n78whI",
                    }
                ]
            },
        )
