"""Common utils."""

import datetime


def get_now():
    """Get now."""
    return datetime.datetime.now(datetime.UTC)
