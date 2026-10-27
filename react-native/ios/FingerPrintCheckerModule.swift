import Foundation
import React

/// React Native module `FingerPrintCheckerModule`. `identify` always RESOLVES exactly once with
/// `{ok: ...}` and never rejects.
@objc(FingerPrintCheckerModule)
public final class FingerPrintCheckerModule: NSObject {
  private let lock = NSLock()
  private var handler: IdentifyHandler? = IdentifyHandler { NativeIdentifier(checker: FingerPrintChecker(config: $0)) }
  private let inflight = InflightTracker()

  @objc public static func requiresMainQueueSetup() -> Bool { false }

  /// Cancels in-flight work; each pending call still resolves `bridge_error`, exactly once.
  @objc public func invalidate() {
    lock.lock()
    let old = handler
    handler = nil
    lock.unlock()
    for entry in inflight.drain() {
      entry.task.cancel()
      entry.once.resolve(Bridge.failure("bridge_error", 0))
    }
    old?.close()
  }

  @objc(identify:resolver:rejecter:)
  public func identify(
    _ args: NSDictionary?, resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    let once = ReplyOnce { resolve($0) }
    lock.lock()
    let active = handler
    lock.unlock()
    guard let active else {
      once.resolve(Bridge.failure("bridge_error", 0))
      return
    }
    let id = UUID()
    let arguments = args as? [String: Any]
    let task = Task { [weak self] in
      let reply = await active.handle(arguments)
      self?.inflight.finish(id)
      once.resolve(Task.isCancelled ? Bridge.failure("bridge_error", 0) : reply)
    }
    if !inflight.register(id, task: task, once: once) {
      // Either the call already finished (reply sent) or the module was invalidated; resolve is idempotent.
      task.cancel()
      lock.lock()
      let invalidated = handler == nil
      lock.unlock()
      if invalidated { once.resolve(Bridge.failure("bridge_error", 0)) }
    }
  }
}
