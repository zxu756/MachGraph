import AppKit
import CoreGraphics
import Foundation

let outPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.png"
let size = 1024
let colorSpace = CGColorSpaceCreateDeviceRGB()
guard let ctx = CGContext(
    data: nil,
    width: size,
    height: size,
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: colorSpace,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    fatalError("Failed to allocate icon context")
}

// Cold Tungsten Steel squircle
let rect = CGRect(x: 56, y: 56, width: 912, height: 912)
let bgPath = CGPath(roundedRect: rect, cornerWidth: 210, cornerHeight: 210, transform: nil)
ctx.addPath(bgPath)
ctx.setFillColor(CGColor(red: 0.059, green: 0.071, blue: 0.086, alpha: 1.0))
ctx.fillPath()
ctx.addPath(bgPath)
ctx.setStrokeColor(CGColor(red: 0.19, green: 0.24, blue: 0.31, alpha: 1.0))
ctx.setLineWidth(14)
ctx.strokePath()

// CFG Directed Edges (True branch amber, False branch green, Unconditional blue)
ctx.setLineWidth(14)
ctx.setStrokeColor(CGColor(red: 0.941, green: 0.533, blue: 0.243, alpha: 0.95))
ctx.move(to: CGPoint(x: 512, y: 690))
ctx.addLine(to: CGPoint(x: 290, y: 500))
ctx.strokePath()

ctx.setStrokeColor(CGColor(red: 0.247, green: 0.725, blue: 0.314, alpha: 0.95))
ctx.move(to: CGPoint(x: 512, y: 690))
ctx.addLine(to: CGPoint(x: 734, y: 500))
ctx.strokePath()

ctx.setStrokeColor(CGColor(red: 0.302, green: 0.639, blue: 1.0, alpha: 0.95))
ctx.move(to: CGPoint(x: 290, y: 420))
ctx.addLine(to: CGPoint(x: 512, y: 245))
ctx.move(to: CGPoint(x: 734, y: 420))
ctx.addLine(to: CGPoint(x: 512, y: 245))
ctx.strokePath()

// 4 Basic Block Nodes
let nodes = [
    CGRect(x: 342, y: 675, width: 340, height: 125),
    CGRect(x: 150, y: 410, width: 280, height: 120),
    CGRect(x: 594, y: 410, width: 280, height: 120),
    CGRect(x: 342, y: 175, width: 340, height: 120)
]
for (idx, box) in nodes.enumerated() {
    let np = CGPath(roundedRect: box, cornerWidth: 24, cornerHeight: 24, transform: nil)
    ctx.addPath(np)
    ctx.setFillColor(CGColor(red: 0.106, green: 0.133, blue: 0.173, alpha: 1.0))
    ctx.fillPath()
    ctx.addPath(np)
    let stroke = idx == 0
        ? CGColor(red: 0.302, green: 0.639, blue: 1.0, alpha: 1.0)
        : CGColor(red: 0.24, green: 0.29, blue: 0.36, alpha: 1.0)
    ctx.setStrokeColor(stroke)
    ctx.setLineWidth(8)
    ctx.strokePath()
}

guard let cgImage = ctx.makeImage() else { fatalError("Failed to render icon") }
let rep = NSBitmapImageRep(cgImage: cgImage)
guard let pngData = rep.representation(using: .png, properties: [:]) else {
    fatalError("Failed to encode PNG")
}
try pngData.write(to: URL(fileURLWithPath: outPath))
