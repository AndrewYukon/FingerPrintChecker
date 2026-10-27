import Flutter
import Foundation

@objc(SwiftFingerPrintCheckerPlugin)
public final class SwiftFingerPrintCheckerPlugin: NSObject, FlutterPlugin {
  static let channelName = "com.fpchecker/flutter"

  private let lock = NSLock()
  private var handler: IdentifyHandler? = IdentifyHandler { NativeIdentifier(checker: FingerPrintChecker(config: $0)) }
  private var inflight: [UUID: (task: Task<Void, Never>, once: ReplyOnce)] = [:]

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: channelName, binaryMessenger: registrar.messenger())
    let instance = SwiftFingerPrintCheckerPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
    registrar.publish(instance)
  }

  /// Cancels in-flight work; each pending call still replies `bridge_error`, exactly once.
  public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
    lock.lock()
    let pending = inflight
    inflight = [:]
    let old = handler
    handler = nil
    lock.unlock()
    for (_, entry) in pending {
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
    lock.lock()
    if handler == nil {
      lock.unlock()
      task.cancel()
      once.resolve(Bridge.failure("bridge_error", 0))
      return
    }
    inflight[id] = (task, once)
    lock.unlock()
  }

  private func finish(_ id: UUID) {
    lock.lock()
    inflight[id] = nil
    lock.unlock()
  }
}
