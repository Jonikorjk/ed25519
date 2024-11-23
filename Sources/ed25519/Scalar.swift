//
//  Scalar.swift
//  
//
//  Created by Yevhenii Serdiukov on 24.11.2024.
//

import Foundation

extension Ed25519.CoreWrapper {
    static func scalarAdd(_ x: String, _ y: String) throws -> String {
        guard let xBytes = Data(hex: x)?.bytes().reversed(), let yBytes = Data(hex: y)?.bytes().reversed() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        let result = Core.scalarAdd(Array(xBytes), Array(yBytes))
        return Data(result).hexEncodedString()
    }

    static func scalarSub(_ x: String, _ y: String) throws -> String {
        guard let xBytes = Data(hex: x)?.bytes().reversed(), let yBytes = Data(hex: y)?.bytes().reversed() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        let result = Core.scalarSub(Array(xBytes), Array(yBytes))
        return Data(result).hexEncodedString()
    }

    static func scalarRandom() -> String {
        Data(Core.scalarRandom()).hexEncodedString()
    }
}
