// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "SessionCore",
    platforms: [.macOS(.v26), .iOS(.v26)],
    products: [
        .library(name: "SessionCore", targets: ["SessionCore"]),
    ],
    dependencies: [
        .package(path: "../RoyalVNCKit"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
    ],
    targets: [
        .target(name: "SessionCore", dependencies: ["RoyalVNCKit"]),
        // In-process RFB 3.8 server that tests drive the Session against. Its RSA-AES side uses CryptoSwift's
        // AES modes, so it shares no cipher code with the client it checks.
        .target(name: "FakeRFBServer", dependencies: ["CryptoSwift"]),
        .testTarget(name: "SessionCoreTests", dependencies: ["SessionCore", "FakeRFBServer"]),
    ]
)
