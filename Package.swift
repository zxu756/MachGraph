// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MachGraph",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "MachGraphModels", targets: ["MachGraphModels"]),
        .library(name: "MachBinaryFormats", targets: ["MachBinaryFormats"]),
        .library(name: "MachA64Decoder", targets: ["MachA64Decoder"]),
        .library(name: "MachCFGEngine", targets: ["MachCFGEngine"]),
        .library(name: "MachMicroDecompiler", targets: ["MachMicroDecompiler"]),
        .library(name: "MachPatchAndHexEngine", targets: ["MachPatchAndHexEngine"]),
        .library(name: "MachProjectStore", targets: ["MachProjectStore"]),
        .library(name: "MachPluginSDK", targets: ["MachPluginSDK"]),
        .library(name: "MachHeadlessCLI", targets: ["MachHeadlessCLI"]),
        .library(name: "MachWorkbenchShell", targets: ["MachWorkbenchShell"]),
        .library(name: "MachStudioViews", targets: ["MachStudioViews"]),
        .executable(name: "MachGraph", targets: ["MachGraph"])
    ],
    targets: [
        .target(
            name: "MachGraphModels",
            dependencies: [],
            linkerSettings: [
                .linkedLibrary("c++abi")
            ]
        ),
        .target(
            name: "MachBinaryFormats",
            dependencies: ["MachGraphModels"]
        ),
        .target(
            name: "MachA64Decoder",
            dependencies: ["MachGraphModels"]
        ),
        .target(
            name: "MachCFGEngine",
            dependencies: [
                "MachGraphModels",
                "MachBinaryFormats",
                "MachA64Decoder"
            ]
        ),
        .target(
            name: "MachMicroDecompiler",
            dependencies: [
                "MachGraphModels",
                "MachA64Decoder",
                "MachCFGEngine"
            ]
        ),
        .target(
            name: "MachPatchAndHexEngine",
            dependencies: [
                "MachGraphModels",
                "MachA64Decoder",
                "MachBinaryFormats"
            ]
        ),
        .target(
            name: "MachProjectStore",
            dependencies: ["MachGraphModels"],
            linkerSettings: [
                .linkedLibrary("sqlite3")
            ]
        ),
        .target(
            name: "MachPluginSDK",
            dependencies: [
                "MachGraphModels",
                "MachBinaryFormats",
                "MachA64Decoder",
                "MachCFGEngine"
            ],
            linkerSettings: [
                .linkedFramework("JavaScriptCore")
            ]
        ),
        .target(
            name: "MachHeadlessCLI",
            dependencies: [
                "MachGraphModels",
                "MachBinaryFormats",
                "MachA64Decoder",
                "MachCFGEngine",
                "MachMicroDecompiler",
                "MachPatchAndHexEngine",
                "MachProjectStore",
                "MachPluginSDK"
            ]
        ),
        .target(
            name: "MachWorkbenchShell",
            dependencies: [
                "MachGraphModels",
                "MachProjectStore",
                "MachPluginSDK"
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI")
            ]
        ),
        .target(
            name: "MachStudioViews",
            dependencies: [
                "MachGraphModels",
                "MachBinaryFormats",
                "MachA64Decoder",
                "MachCFGEngine",
                "MachMicroDecompiler",
                "MachPatchAndHexEngine",
                "MachProjectStore",
                "MachPluginSDK",
                "MachHeadlessCLI",
                "MachWorkbenchShell"
            ],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI")
            ]
        ),
        .executableTarget(
            name: "MachGraph",
            dependencies: [
                "MachGraphModels",
                "MachBinaryFormats",
                "MachA64Decoder",
                "MachCFGEngine",
                "MachMicroDecompiler",
                "MachPatchAndHexEngine",
                "MachProjectStore",
                "MachPluginSDK",
                "MachHeadlessCLI",
                "MachWorkbenchShell",
                "MachStudioViews"
            ]
        ),
        .testTarget(
            name: "MachGraphTests",
            dependencies: [
                "MachGraphModels",
                "MachBinaryFormats",
                "MachA64Decoder",
                "MachCFGEngine",
                "MachMicroDecompiler",
                "MachPatchAndHexEngine",
                "MachProjectStore",
                "MachPluginSDK",
                "MachHeadlessCLI",
                "MachWorkbenchShell",
                "MachStudioViews"
            ]
        )
    ]
)
