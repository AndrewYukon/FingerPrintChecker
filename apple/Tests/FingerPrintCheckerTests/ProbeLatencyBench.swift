import XCTest
@testable import FingerPrintChecker

/// Measures each integrity probe on a real iPhone (M22). Reports instead of asserting a speed, so a slow device shows
/// up as numbers rather than a flaky red. Skipped everywhere except a physical iOS device:
/// `xcodebuild test -scheme FingerPrintChecker -destination 'id=<udid>' -only-testing:FingerPrintCheckerTests/ProbeLatencyBench`.
/// The first pass is the first probe run in the test process, so it includes cold costs (dyld walk, CFNetwork load).
final class ProbeLatencyBench: XCTestCase {
    private static let warmRuns = 40

    func testPerProbeLatency() async throws {
        #if os(iOS) && !targetEnvironment(simulator)
        let env = SystemProbeEnvironment()
        let probes = allProbes
        let cold = probes.map { probe in (probe.code, timeMs { _ = try? probe.run(env) }) }
        let warm = probes.map { probe in (0..<Self.warmRuns).map { _ in timeMs { _ = try? probe.run(env) } }.sorted() }
        var wall = [Double]()
        for _ in 0..<Self.warmRuns {
            let start = DispatchTime.now().uptimeNanoseconds
            _ = await IntegrityProbes.collect(env: env, platform: .ios)
            wall.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
        }
        wall.sort()

        var lines = zip(cold, warm).map { coldEntry, w in
            pad(coldEntry.0) + String(format: " cold %7.1f  warm p50 %6.1f  p95 %6.1f  max %6.1f",
                                      coldEntry.1, w[w.count / 2], w[w.count * 95 / 100], w.last!)
        }
        lines.append(pad("collect()") + String(format: "       p50 %6.1f  p95 %6.1f  max %6.1f",
                                               wall[wall.count / 2], wall[wall.count * 95 / 100], wall.last!))
        print("FpcProbeLatency\n" + lines.joined(separator: "\n"))
        XCTAssertEqual(cold.count, probes.count)
        #else
        throw XCTSkip("per-probe latency is only meaningful on a physical iOS device")
        #endif
    }

    private func pad(_ text: String) -> String {
        text.padding(toLength: 14, withPad: " ", startingAt: 0)
    }

    private func timeMs(_ block: () -> Void) -> Double {
        let start = DispatchTime.now().uptimeNanoseconds
        block()
        return Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }
}
