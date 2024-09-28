"""Constants for the HA integration."""

import datetime

DOMAIN = "airmate_cn"

CONF_ACCOUNT = "account"
CONF_REFRESH_TOKEN = "refresh_token"

API_BASE_CFG = "eyJhcHBfaWQiOiIzMDAwMiIsImFwcF9rZXkiOiJkYjcwNGViNjA0MmU0MDQyODE4MmQxM2Y5MGFiN2U5YiIsImFwcF9zZWNyZXQiOiJkODRmN2E2YjJhNDA0MzczOGQ2MTU3OWRjZTZjNzc4OSJ9"

DEFAULT_API_HOST = "https://api-life.worthcloud.net"
DEFAULT_MSG_API_HOST = "https://api-life-msg.worthcloud.net"
X_USER_AGENT = "iOS_WCloud/1.2.1 (iPhone; iOS 17.5.1; Scale/3.00)"
HTTPX_TIMEOUT = 30.0

AUTH_VALID_OFFSET = datetime.timedelta(hours=5)
EXPIRES_AT_OFFSET = datetime.timedelta(seconds=HTTPX_TIMEOUT * 4)
