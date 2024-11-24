//
//  Scalar.swift
//  
//
//  Created by Yevhenii Serdiukov on 23.11.2024.
//

import Clibsodium

extension Ed25519.CoreWrapper.Core {
    /// a - b = c
    ///
    /// Subtracts two scalars
    ///
    /// # Parameters
    /// - x - little-endian bytes scalar representation
    /// - y - little-endian bytes scalar representation
    ///
    /// # Output
    /// Returns little-endian scalar bytes
    static func scalarSub(_ x: [UInt8], _ y: [UInt8]) -> [UInt8] {
        var x = x
        var y = y

        padEndZerosIfNeeded(elem: &x)
        padEndZerosIfNeeded(elem: &y)

        var z = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_sub(&z, x, y)

        return Array(z.reversed())
    }

    /// a + b = c
    ///
    /// Adds two scalars
    ///
    /// # Parameters
    /// - x - little-endian bytes scalar representation
    /// - y - little-endian bytes scalar representation
    ///
    /// # Output
    /// Returns little-endian scalar bytes
    static func scalarAdd(_ x: [UInt8], _ y: [UInt8]) -> [UInt8] {
        var x = x
        var y = y

        padEndZerosIfNeeded(elem: &x)
        padEndZerosIfNeeded(elem: &y)

        var z = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_add(&z, x, y)

        return Array(z.reversed())
    }

    /// Returns random little-endian scalar bytes
    static func scalarRandom() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_random(&bytes)
        padEndZerosIfNeeded(elem: &bytes)
        return bytes
    }
}
