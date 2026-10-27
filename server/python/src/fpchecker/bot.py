"""Bot check helpers: the forwardable header map and the typed ``bot`` signal."""
from __future__ import annotations

from typing import Any, Dict, Mapping

# The only request headers ``bot_check`` needs. Never Cookie or Authorization.
BOT_CHECK_HEADERS = frozenset(
    {
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
        "signature",
        "signature-input",
        "signature-agent",
        "upgrade-insecure-requests",
    }
)


def bot_check_headers(headers: Mapping[str, Any]) -> Dict[str, str]:
    """Build the header map for ``FpChecker.bot_check`` from a request's headers.

    Works with any mapping that has ``items()`` (a dict, Starlette/FastAPI ``request.headers``,
    Flask ``request.headers``, Django ``request.headers``). Keeps only the allowed headers with
    lower-cased names and drops everything else, including Cookie and Authorization. A header that
    appears more than once is joined with ", ".
    """
    out: Dict[str, str] = {}
    for name, value in headers.items():
        key = str(name).lower()
        if key not in BOT_CHECK_HEADERS or value is None:
            continue
        text = ", ".join(str(v) for v in value) if isinstance(value, (list, tuple)) else str(value)
        out[key] = f"{out[key]}, {text}" if key in out else text
    return out
