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
    ],
    targets: [
        .target(name: "SessionCore", dependencies: ["RoyalVNCKit"]),
        // In-process RFB 3.8 server that tests drive the Session against.
        .target(name: "FakeRFBServer"),
        .testTarget(name: "SessionCoreTests", dependencies: ["SessionCore", "FakeRFBServer"]),
    ]
)
