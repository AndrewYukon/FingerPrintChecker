import Flutter
import Foundation

@objc(SwiftFingerPrintCheckerPlugin)
public final class SwiftFingerPrintCheckerPlugin: NSObject, FlutterPlugin {
  static let channelName = "com.fpchecker/flutter"

  private let lock = NSLock()
  private var handler: IdentifyHandler? = IdentifyHandler { NativeIdentifier(checker: FingerPrintChecker(config: $0)) }
  private let inflight = InflightTracker()

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: channelName, binaryMessenger: registrar.messenger())
    let instance = SwiftFingerPrintCheckerPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
    registrar.publish(instance)
  }

  /// Cancels in-flight work; each pending call still replies `bridge_error`, exactly once.
  public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
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

  /// Always replies exactly once with `{ok: ...}`, on the main thread; never calls `FlutterError`.
  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard call.method == "identify" else {
      DispatchQueue.main.async { result(FlutterMethodNotImplemented) }
      return
    }
    let once = ReplyOnce { reply in
      if Thread.isMainThread { result(reply) } else { DispatchQueue.main.async { result(reply) } }
    }
    lock.lock()
    let active = handler
    lock.unlock()
    guard let active else {
      once.resolve(Bridge.failure("bridge_error", 0))
      return
    }
    let id = UUID()
    let arguments = call.arguments
    let task = Task { [weak self] in
      let reply = await active.handle(arguments)
      self?.finish(id)
      once.resolve(Task.isCancelled ? Bridge.failure("bridge_error", 0) : reply)
    }
    if !inflight.register(id, task: task, once: once) {
      // Either the call already finished (reply sent) or the engine detached; resolve is idempotent.
      task.cancel()
      lock.lock()
      let detached = handler == nil
      lock.unlock()
      if detached { once.resolve(Bridge.failure("bridge_error", 0)) }
    }
  }

  private func finish(_ id: UUID) { inflight.finish(id) }
}
