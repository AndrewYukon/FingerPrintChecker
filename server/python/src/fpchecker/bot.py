"""Bot check helpers: the forwardable header map and the typed ``bot`` signal."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping

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


# Never forwarded, even when a signature covers them: they carry credentials.
_NEVER_FORWARD = frozenset({"cookie", "authorization", "proxy-authorization"})
_MAX_EXTRA = 32


def _covered_headers(signature_input: str) -> List[str]:
    """Non-``@`` component names covered by a ``signature-input`` value (lower-cased)."""
    names: List[str] = []
    for lst in re.findall(r"\(([^)]*)\)", signature_input):
        for q in re.findall(r'"([^"]*)"', lst):
            n = q.lower()
            if n and not n.startswith("@"):
                names.append(n)
    return names


def bot_check_headers(headers: Mapping[str, Any]) -> Dict[str, str]:
    """Build the header map for ``FpChecker.bot_check`` from a request's headers.

    Works with any mapping that has ``items()`` (a dict, Starlette/FastAPI ``request.headers``,
    Flask ``request.headers``, Django ``request.headers``). Keeps the allowed headers plus any header named
    as a covered component in the request's ``signature-input`` (so a signed request can be verified), with
    lower-cased names. Drops everything else; Cookie and Authorization are never forwarded. A header that
    appears more than once is joined with ", ".
    """
    every: Dict[str, str] = {}
    for name, value in headers.items():
        if value is None:
            continue
        key = str(name).lower()
        text = ", ".join(str(v) for v in value) if isinstance(value, (list, tuple)) else str(value)
        every[key] = f"{every[key]}, {text}" if key in every else text
    wanted = set(BOT_CHECK_HEADERS)
    extra = [n for n in _covered_headers(every.get("signature-input", "")) if n not in _NEVER_FORWARD]
    wanted.update(extra[:_MAX_EXTRA])
    return {k: v for k, v in every.items() if k in wanted}
