import FingerPrintChecker
import SwiftUI

struct ContentView: View {
    @State private var output = "Press Identify."
    @State private var busy = false
    private let checker = DemoConfig.load().map(FingerPrintChecker.init(config:))
    private let intentURL = DemoConfig.intentURL()
    private let config = DemoConfig.load()
    @State private var round = "r1"

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button(busy ? "Working..." : "Identify v1") { run() }
                    .disabled(busy || checker == nil)
                if let intentURL {
                    Button("Identify v2") { runV2(intentURL) }
                        .disabled(busy || checker == nil)
                }
            }
            if let intentURL, let config {
                HStack {
                    TextField("round", text: $round)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .frame(maxWidth: 80)
                    Button("Claim test") { claim(intentURL, config) }
                        .disabled(busy || !MatrixClaim.isRound(round))
                }
            }
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
        // Scripted end-to-end runs: `simctl launch <device> <bundle> -autoIdentify` identifies once on launch.
        .onAppear { if ProcessInfo.processInfo.arguments.contains("-autoIdentify") { run() } }
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

    private func runV2(_ url: URL) {
        guard let checker else { return }
        busy = true
        Task {
            switch await DemoConfig.fetchIntent(from: url) {
            case .failure(let e):
                output = "INTENT FAILURE\nreason: \(e.reason)\nhttpStatus: \(e.httpStatus)"
            case .success(let token):
                output = Self.describe(await checker.identify(intentToken: token))
            }
            busy = false
        }
    }

    /// Internal test (MatrixClaim): one real claim of the round in the field.
    private func claim(_ url: URL, _ config: FPConfig) {
        busy = true
        Task {
            let line = await MatrixClaim.run(round: round, intentURL: url, config: config)
            output = line + "\n\n" + output
            busy = false
        }
    }

    private static func describe(_ result: FPResultV2) -> String {
        switch result {
        case .failure(let reason, let status):
            return "V2 FAILURE\nreason: \(reason)\nhttpStatus: \(status)"
        case .success(let s):
            return """
            V2 SUCCESS
            attestation: \(s.attestation.prefix(24))…
            visitorId: \(s.visitorId ?? "hidden (scoreDetails)")
            trustScore: \(s.trustScore.map(String.init) ?? "hidden (scoreDetails)")
            identityConfidence: \(s.identityConfidence.map(String.init) ?? "hidden (scoreDetails)")
            isNew: \(s.isNew.map(String.init) ?? "-")
            proofStatus: \(s.proofStatus ?? "-")
            deductions: \(s.trustDeductions.map { $0.isEmpty ? "-" : $0.joined(separator: ", ") } ?? "-")

            \(prettyJSON(s.raw))
            """
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
            trustScore: \(s.trustScore.map(String.init) ?? "hidden (scoreDetails)")
            identityConfidence: \(s.identityConfidence.map(String.init) ?? "hidden (scoreDetails)")
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
