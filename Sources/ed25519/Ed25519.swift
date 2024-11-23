//
//  Ed25519.swift
//
//
//  Created by Yevhenii Serdiukov on 23.11.2024.
//

import Foundation

enum Ed25519WrapperError: LocalizedError {
    case invalidPointLenth(length: [Int])
    case ed25519InvalidPoint
    case failedToDecodeHex

    var errorDescription: String? {
        switch self {
        case .invalidPointLenth(let debugLength):
            return "Point bytes count required to be 32, but received: \(debugLength)"
        case .ed25519InvalidPoint:
            return "Received point that is not contains in Ed25519"
        case .failedToDecodeHex:
            return "Failed"
        }
    }
}

enum Ed25519 {
    enum CoreWrapper {
        enum Core {
            static func padEndZerosIfNeeded(elem: inout [UInt8]) {
                while elem.count < 32 {
                    elem.append(0)
                }
            }
        }
    }

    enum Sign {}

    enum Verify {}
}
