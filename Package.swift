// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FingerPrintChecker",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(name: "FingerPrintChecker", targets: ["FingerPrintChecker"]),
    ],
    targets: [
        .target(
            name: "FingerPrintChecker",
            path: "apple/Sources/FingerPrintChecker",
            resources: [.process("Resources/PrivacyInfo.xcprivacy")]
        ),
        .testTarget(
            name: "FingerPrintCheckerTests",
            dependencies: ["FingerPrintChecker"],
            path: "apple/Tests/FingerPrintCheckerTests"
        ),
    ]
)
