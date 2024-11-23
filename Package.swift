// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ed25519",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "ed25519",
            targets: ["ed25519"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "ed25519",
            resources: [
                .copy("Frameworks/Clibsodium.xcframework"),
            ]
        ),
        .testTarget(
            name: "ed25519Tests",
            dependencies: ["ed25519"]
        ),
    ]
)
