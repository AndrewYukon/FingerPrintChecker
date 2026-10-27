import Foundation

private final class OneShot: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false

    func fire() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if fired { return false }
        fired = true
        return true
    }
}

/// Runs `operation`, giving up after `seconds`. Unlike a task group this never waits for an operation
/// that ignores cancellation (system callbacks), so a hung Apple service cannot hang identify.
func withDeadline<T: Sendable>(
    seconds: Double, _ operation: @escaping @Sendable () async -> T
) async -> T? {
    await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
        let once = OneShot()
        let work = Task {
            let value = await operation()
            if once.fire() { continuation.resume(returning: value) }
        }
        Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            if once.fire() {
                work.cancel()
                continuation.resume(returning: nil)
            }
        }
    }
}

/// FIFO async mutex so concurrent `identify()` calls cannot interleave App Attest assertions
/// (the server requires strictly increasing counters).
actor AsyncLock {
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !locked { locked = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty { locked = false } else { waiters.removeFirst().resume() }
    }
}
