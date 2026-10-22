// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "RoyalVNCKit",

    platforms: [
        .macOS(.v26),
        .iOS(.v26)
    ],

    products: [
        .library(name: "RoyalVNCKit", targets: [ "RoyalVNCKit" ])
    ],

    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0")
    ],

    targets: [
        .target(name: "RoyalVNCKitC"),

        .target(
            name: "RoyalVNCKit",
            dependencies: [
                "RoyalVNCKitC",
                "d3des",
                "Z",
                "CryptoSwift"
            ],
            swiftSettings: [
                .swiftLanguageMode(.v5)
            ]
        ),

        .target(name: "d3des"),

        .target(name: "Z", linkerSettings: [
            .linkedLibrary("z")
        ])
    ]
)
