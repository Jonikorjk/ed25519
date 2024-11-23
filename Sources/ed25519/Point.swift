//
//  Untitled.swift
//  
//
//  Created by Yevhenii Serdiukov on 24.11.2024.
//

import Foundation

extension Ed25519.CoreWrapper {
    static func basePointMulScalarNoclamp(_ scalar: String) throws -> String {
        guard let scalarBytes = Data(hex: scalar)?.bytes().reversed() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        let q = try Core.basePointMulScalarNoclamp(Array(scalarBytes))
        return Data(q).hexEncodedString()
    }

    static func basePointMulScalar(_ scalar: String) throws -> String {
        guard let scalarBytes = Data(hex: scalar)?.bytes().reversed() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        let q = try Core.basePointMulScalar(Array(scalarBytes))
        return Data(q).hexEncodedString()
    }

    static func addPoints(_ p: String, _ q: String) throws -> String {
        guard let pBytes = Data(hex: p)?.bytes(), let qBytes = Data(hex: q)?.bytes() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        let rBytes = try Core.addPoints(pBytes, qBytes)
        return Data(rBytes).hexEncodedString()
    }

    static func subPoints(_ p: String, _ q: String) throws -> String {
        guard let pBytes = Data(hex: p)?.bytes(), let qBytes = Data(hex: q)?.bytes() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        let rBytes = try Core.subPoints(pBytes, qBytes)
        return Data(rBytes).hexEncodedString()
    }

    static func isValidPoint(_ p: String) throws -> Bool {
        guard let pBytes = Data(hex: p)?.bytes().reversed() else {
            throw Ed25519WrapperError.failedToDecodeHex
        }

        return try Core.isValidPoint(Array(pBytes))
    }
}
