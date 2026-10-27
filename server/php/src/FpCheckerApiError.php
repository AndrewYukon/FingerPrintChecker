<?php

declare(strict_types=1);

namespace FpChecker;

use RuntimeException;

/** Non-2xx response (status >= 100) or a transport failure (status 0, code "network_error" / "timeout"). */
class FpCheckerApiError extends RuntimeException
{
    private int $httpStatus;
    private ?string $errorCode;
    private ?int $retryAfterSeconds;
    private mixed $responseBody;

    public function __construct(int $status, ?string $code, ?int $retryAfter = null, mixed $body = null)
    {
        // The message carries only status and code: never the request, headers or response body.
        parent::__construct('FpChecker API error: status=' . $status . ' code=' . ($code ?? 'none'));
        $this->httpStatus = $status;
        $this->errorCode = $code;
        $this->retryAfterSeconds = $retryAfter;
        $this->responseBody = $body;
    }

    public function status(): int
    {
        return $this->httpStatus;
    }

    /** `getCode()` is final in Exception, so the API error code lives here. */
    public function code(): ?string
    {
        return $this->errorCode;
    }

    public function retryAfter(): ?int
    {
        return $this->retryAfterSeconds;
    }

    public function body(): mixed
    {
        return $this->responseBody;
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return [
            'message' => $this->getMessage(),
            'status' => $this->httpStatus,
            'errorCode' => $this->errorCode,
            'retryAfter' => $this->retryAfterSeconds,
        ];
    }
}
