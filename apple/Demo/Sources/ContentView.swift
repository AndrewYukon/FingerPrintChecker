import FingerPrintChecker
import SwiftUI

struct ContentView: View {
    @State private var output = "Press Identify."
    @State private var busy = false
    private let checker = DemoConfig.load().map(FingerPrintChecker.init(config:))

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button(busy ? "Working..." : "Identify") { run() }
                .disabled(busy || checker == nil)
            if checker == nil {
                Text("Missing keys: copy Config.example.xcconfig to Config.xcconfig, fill it in and regenerate the project.")
                    .foregroundColor(.red)
            }
            ScrollView {
                Text(output)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding()
        .frame(minWidth: 320, minHeight: 360)
    }

    private func run() {
        guard let checker else { return }
        busy = true
        Task {
            let result = await checker.identify()
            output = Self.describe(result)
            busy = false
        }
    }

    private static func describe(_ result: FPResult) -> String {
        switch result {
        case .failure(let reason, let status):
            return "FAILURE\nreason: \(reason)\nhttpStatus: \(status)"
        case .success(let s):
            let raw = prettyJSON(s.raw)
            return """
            SUCCESS
            visitorId: \(s.visitorId)
            trustScore: \(s.trustScore)
            identityConfidence: \(s.identityConfidence)
            isNew: \(s.isNew)
            proofStatus: \(s.proofStatus ?? "-")
            deductions: \(s.trustDeductions.isEmpty ? "-" : s.trustDeductions.joined(separator: ", "))

            \(raw)
            """
        }
    }

    private static func prettyJSON(_ data: Data) -> String {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        else { return String(data: data, encoding: .utf8) ?? "" }
        return String(data: pretty, encoding: .utf8) ?? ""
    }
}
