# fingerprintchecker (Python)

Install with `pip install fingerprintchecker`; import it as `fpchecker`.

Server SDK for [FingerPrintChecker](https://fpchecker.com). Python 3.9+, standard-library HTTP, one runtime dependency (`cryptography`, for sealed results).

```python
from fpchecker import FpChecker, unseal_result, verify_webhook_signature, FpCheckerApiError

fp = FpChecker(os.environ["FPCHECKER_SECRET_KEY"])
verdict = fp.check_eligibility({"visitorId": "v_..."})
if verdict.get("ok") is False:
    print("refused:", verdict.get("error") or verdict.get("reason"))
```

## Client

`FpChecker(secret_key, base_url="https://api.fpchecker.com", timeout=10, *, publishable_key=None)` has one method per OpenAPI `operationId`, in snake_case: `create_intent`, `get_challenge`, `identify`, `check_eligibility`, `release_eligibility`, `check_quota`, `bind_subject`, `relate_subjects`, `send_feedback`, `get_claim_flags`, `search_events`, `get_event`, `update_event`, `get_visitor`, `delete_visitor`, `get_health`, `get_status`. Bodies and query parameters are plain dicts; responses are dicts.

- The secret key goes in the `X-Secret-Key` header, never in a URL, and is not shown by `repr()`. `get_challenge` and `identify` use the publishable key (`publishable_key=`) in `X-Publishable-Key` instead; `get_health` and `get_status` send no key.
- 2xx responses are returned as data, **including** refusals such as `{"ok": False, "error": ...}`. Check `ok`.
- Non-2xx raises `FpCheckerApiError` with `status`, `code` (`error` or `reason` from the body), `retry_after` (seconds) and `body`.
- Network failures and timeouts also raise `FpCheckerApiError`, with `status` 0, `code` `"network_error"` or `"timeout"`, and the original exception as `__cause__`.
- Redirects are never followed (they would forward the secret key to another origin). `base_url` must be https, except localhost, 127.0.0.1 and [::1] (otherwise `ValueError`).
- `timeout` (positive finite seconds) applies per network operation (connect, each read), not to the whole call.
- Only GET requests retry (429, 5xx, network failures and timeouts; at most 2 retries, honouring `Retry-After`, wait capped at 10 s). POST, PATCH and DELETE are never retried.

## Sealed results

```python
result = unseal_result(identify_response["sealedResult"], [os.environ["FPC_SEALED_KEY"]])
```

Pass every active key (active and previous during rotation). Raises `SealedResultError` with `.code` of `bad_format`, `unknown_key`, `decrypt_failed`, `invalid_key` or `unsupported_version`.

## Webhooks

```python
# raw_body must be the exact bytes received, not a re-serialised object.
verify_webhook_signature(request.body, request.headers["FPC-Signature"], os.environ["FPC_WEBHOOK_SECRET"])
```

Raises `WebhookSignatureError` with `.code` of `malformed_header`, `bad_signature`, `expired` or `future`. `tolerance_sec` (default 300) must be a finite number >= 0, else `TypeError` / `ValueError`.

## License

Apache-2.0
