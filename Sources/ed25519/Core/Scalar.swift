//
//  Scalar.swift
//  
//
//  Created by Yevhenii Serdiukov on 23.11.2024.
//

import Clibsodium

extension Ed25519.CoreWrapper.Core {
    static func scalarSub(_ x: [UInt8], _ y: [UInt8]) -> [UInt8] {
        var x = x
        var y = y

        padEndZerosIfNeeded(elem: &x)
        padEndZerosIfNeeded(elem: &y)

        var z = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_sub(&z, x, y)

        return Array(z.reversed())
    }

    static func scalarAdd(_ x: [UInt8], _ y: [UInt8]) -> [UInt8] {
        var x = x
        var y = y

        padEndZerosIfNeeded(elem: &x)
        padEndZerosIfNeeded(elem: &y)

        var z = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_add(&z, x, y)

        return Array(z.reversed())
    }

    static func scalarRandom() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_random(&bytes)
        padEndZerosIfNeeded(elem: &bytes)
        return bytes
    }
}
