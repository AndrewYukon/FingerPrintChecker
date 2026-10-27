<?php

declare(strict_types=1);

namespace FpChecker\Tests;

/** A real HTTP server (`php -S`) for tests that need a socket. */
final class PhpServer
{
    public int $port;
    /** @var resource */
    private $proc;

    /** @param array<string, string> $env */
    public function __construct(string $router, array $env = [])
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $this->port = (int) substr((string) strrchr((string) stream_socket_get_name($probe, false), ':'), 1);
        fclose($probe);
        $cmd = [PHP_BINARY, '-S', '127.0.0.1:' . $this->port, '-t', __DIR__ . '/fixtures', __DIR__ . '/fixtures/' . $router];
        $proc = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, null, array_merge(getenv(), $env));
        if (!is_resource($proc)) {
            throw new \RuntimeException('cannot start php -S');
        }
        $this->proc = $proc;
        for ($i = 0; $i < 100; $i++) {
            $s = @fsockopen('127.0.0.1', $this->port, $errno, $errstr, 0.2);
            if ($s !== false) {
                fclose($s);
                return;
            }
            usleep(50_000);
        }
        $this->stop();
        throw new \RuntimeException('php -S did not start');
    }

    public function url(): string
    {
        return 'http://127.0.0.1:' . $this->port;
    }

    public function stop(): void
    {
        proc_terminate($this->proc);
        proc_close($this->proc);
    }
}
