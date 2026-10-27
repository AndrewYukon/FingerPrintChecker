package com.fpchecker.server;

import java.time.Duration;

/** Test seam for retry waits. */
interface Sleeper {
    void sleep(Duration duration) throws InterruptedException;

    Sleeper REAL = duration -> Thread.sleep(duration.toMillis());
}
