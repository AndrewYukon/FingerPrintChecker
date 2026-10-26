import CFNetwork
import Foundation
import MachO
#if os(iOS)
import CoreLocation
#endif

/// Real device readings. Nothing here prompts the user, requests a permission or reports a coordinate.
struct SystemProbeEnvironment: ProbeEnvironment {
    func fileExists(_ path: String) -> Bool {
        access(path, F_OK) == 0
    }

    func canWriteOutsideSandbox() -> Bool {
        let path = "/private/fpc-\(UUID().uuidString)"
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { return false }
        close(fd)
        unlink(path)
        return true
    }

    func loadedImageNames() -> [String] {
        (0..<_dyld_image_count()).compactMap { index in
            _dyld_get_image_name(index).map { String(cString: $0) }
        }
    }

    /// Non-blocking connect to 127.0.0.1 bounded by `poll`.
    func canConnectLocal(port: UInt16, timeout: TimeInterval) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else { return false }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var pollFd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pollFd, 1, Int32(timeout * 1000)) > 0 else { return false }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { return false }
        return error == 0
    }

    func environment(_ name: String) -> String? {
        ProcessInfo.processInfo.environment[name]
    }

    func isTraced() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    func proxySettings() -> [String: Any]? {
        CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
    }

    /// Only when the host app already holds location authorisation, and only the cached fix: never asks,
    /// never starts updates, never reads the coordinates.
    func locationSimulated() -> Bool? {
        #if os(iOS)
        guard #available(iOS 15.0, *) else { return nil }
        let manager = CLLocationManager()
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways: break
        default: return nil
        }
        return manager.location?.sourceInformation?.isSimulatedBySoftware
        #else
        return nil
        #endif
    }
}
