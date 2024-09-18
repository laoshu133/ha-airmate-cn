"""API utils."""

from collections import deque
from dataclasses import dataclass
import datetime
from hashlib import md5
import io
import json
import logging
import mimetypes

import httpx

_LOGGER = logging.getLogger(__name__)


@dataclass
class AnonymizedResponse:
    """An anonymized response."""

    filename: str
    content: list | None = None


class APIError(Exception):
    """General API error."""

    def __init__(
        self, message: str, *, response: httpx.Response, request: httpx.Request | None
    ) -> None:
        """Initialize the API error."""
        super().__init__(message)


class AuthError(APIError):
    """Auth-related error from API (HTTP status codes 401 and 403)."""


class QuotaError(APIError):
    """Quota exceeded on API."""


def anonymize_data(json_data: list | dict) -> list | dict:
    """For replace parts of the logfiles."""

    return json_data


def anonymize_response(response: httpx.Response) -> AnonymizedResponse:
    """Anonymize a responses URL and content."""
    brand = "xiaotu"

    url_parts = response.url.path.split("/")[1:]
    url_path = "_".join(url_parts)

    try:
        content: list | dict | str
        content = anonymize_data(response.json())
    except json.JSONDecodeError:
        content = response.text

    content_type = next(
        iter((response.headers.get("content-type") or "").split(";")), ""
    )
    file_extension = mimetypes.guess_extension(content_type or ".txt")

    return AnonymizedResponse(f"{brand}{url_path}{file_extension}", content)


async def handle_httpstatuserror(
    ex: httpx.HTTPStatusError,
    module: str = "API",
    log_handler: list[logging.Logger] | None = None,
    dont_raise: bool = False,
) -> None:
    """Try to extract information from response and re-raise Exception."""
    _logger = log_handler or logging.getLogger(__name__)
    _level = logging.DEBUG if dont_raise else logging.ERROR

    await ex.response.aread()

    # By default we will raise a APIError
    _ex_to_raise = APIError

    # Quota errors can either be 429 Too Many Requests or 403 Quota Exceeded (instead of 401 Forbidden)
    if (
        ex.response.status_code == 429
        or (ex.response.status_code == 403 and "quota" in ex.response.text.lower())
    ) and module != "AUTH":
        _ex_to_raise = QuotaError

    # HTTP status code is 401 or 403, raise AuthError instead
    # Always raise AuthError as final when logging in (e.g. HTTP 429 should still be AuthError)
    elif ex.response.status_code in [401, 403] or module == "AUTH":
        _ex_to_raise = AuthError

    try:
        # Try parsing the known API error JSON
        _err = ex.response.json()
        _err_message = f'{type(ex).__name__}: {_err["error"]} - {_err.get("error_description", "")}'
    except (json.JSONDecodeError, KeyError):
        # If format has changed or is not JSON
        _err_message = f"{type(ex).__name__}: {ex.response.text or str(ex)}"

    _logger.log(_level, "%s due to %s", _ex_to_raise.__name__, _err_message)

    if not dont_raise:
        raise _ex_to_raise(ex)


def sign_request(api: httpx.AsyncClient, request: httpx.Request) -> httpx.Request:
    """Sign a request."""

    is_msg_api = "api-life-msg" in request.url.host

    # Add base headers
    request.headers["app_key"] = api.app_key

    # Add app_id if it is msg API
    if is_msg_api:
        request.headers["app_id"] = api.app_id

    # Add timestamp
    if not request.headers.get("ts"):
        request.headers["ts"] = str(int(datetime.datetime.now().timestamp()))

    param_map = {}

    # Add body
    if request.headers.get("Content-Type") == "application/json":
        body_str = request_body_to_string(request)
        if body_str:
            param_map["body"] = body_str

    # Sign keys
    sign_keys = ["app_id", "app_key", "ts", "Authorization"]
    for key in sign_keys:
        if request.headers.get(key):
            param_map[key] = request.headers[key]

    # Sign the data
    sn = sign_data(param_map, api.app_secret)

    # Add sn to headers
    request.headers["sn"] = sn

    return request

def sign_data(data: dict, secret: str) -> str:
    """Sign data with a secret key."""

    hash_map = {}

    if data and len(data) > 0:
        for key, value in data.items():
            if isinstance(value, list):
                hash_map[key] = json.dumps(value)
            else:
                hash_map[key] = value

    # Sort keys
    sorted_keys = sorted(hash_map.keys())

    # Create param string
    param_string = "&".join(f"{key}={hash_map[key]}" for key in sorted_keys)

    # Add secret
    final_string = f"{param_string}&{secret}"

    return md5(final_string.encode()).hexdigest()


def request_body_to_string(request: httpx.Request) -> str:
    """Convert the request body to a string."""

    content = request.content

    if content is None:
        return ""

    try:
        if isinstance(content, bytes):
            return content.decode("utf-8")

        if isinstance(content, (str, int, float, bool)):
            return str(content)

        # Read the stream
        buffer = io.BytesIO()
        for chunk in request.stream():
            buffer.write(chunk)

        return buffer.getvalue().decode("utf-8")
    except Exception as e:  # noqa: BLE001
        _LOGGER.debug("Error converting request body to string: %s", e)

        return ""


# Cache response content for logging.
RESPONSE_STORE: list[deque[AnonymizedResponse]] = deque(maxlen=10)
