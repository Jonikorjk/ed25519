//
//  Points.swift
//
//
//  Created by Yevhenii Serdiukov on 23.11.2024.
//

import Clibsodium

extension Ed25519.CoreWrapper.Core {
    /// Calculates the point without clamping the scalar.
    /// # Parameters
    /// - scalar - scalar bytes in the big-endian order.
    /// # Output
    /// Returns the point bytes in little-endian order.
    static func basePointMulScalarNoclamp(_ scalar: [UInt8]) throws -> [UInt8] {
        var scalar = scalar
        padEndZerosIfNeeded(elem: &scalar)

        var q = [UInt8](repeating: 0, count: 32)
        crypto_scalarmult_ed25519_base_noclamp(&q, scalar)

        if q.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [q.count])
        }

        if crypto_core_ed25519_is_valid_point(q) != 1 {
            throw Ed25519WrapperError.ed25519InvalidPoint
        }

        return q
    }

    static func basePointMulScalar(_ scalar: [UInt8]) throws -> [UInt8] {
        var scalar = scalar
        padEndZerosIfNeeded(elem: &scalar)

        var q = [UInt8](repeating: 0, count: 32)
        crypto_scalarmult_ed25519_base(&q, scalar)

        if q.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [q.count])
        }

        if crypto_core_ed25519_is_valid_point(q) != 1 {
            throw Ed25519WrapperError.ed25519InvalidPoint
        }

        return q

    }

    static func addPoints(_ p: [UInt8], _ q: [UInt8]) throws -> [UInt8] {
        var p = p
        var q = q

        padEndZerosIfNeeded(elem: &p)
        padEndZerosIfNeeded(elem: &q)

        if p.count != 32 || q.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [p.count, q.count])
        }

        var r = [UInt8].init(repeating: 0, count: 32)
        crypto_core_ed25519_add(&r, p, q)

        if r.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [r.count])
        }

        if crypto_core_ed25519_is_valid_point(r) != 1 {
            throw Ed25519WrapperError.ed25519InvalidPoint
        }

        return r
    }

    static func subPoints(_ p: [UInt8], _ q: [UInt8]) throws -> [UInt8] {
        var p = p
        var q = q

        padEndZerosIfNeeded(elem: &p)
        padEndZerosIfNeeded(elem: &q)

        if p.count != 32 || q.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [p.count, q.count])
        }

        var r = [UInt8].init(repeating: 0, count: 32)
        crypto_core_ed25519_sub(&r, p, q)

        if r.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [r.count])
        }

        if crypto_core_ed25519_is_valid_point(r) != 1 {
            throw Ed25519WrapperError.ed25519InvalidPoint
        }

        return r
    }

    static func isValidPoint(_ p: [UInt8]) throws -> Bool {
        var p = p

        padEndZerosIfNeeded(elem: &p)

        if p.count != 32 {
            throw Ed25519WrapperError.invalidPointLenth(length: [p.count])
        }

        return crypto_core_ed25519_is_valid_point(p) == 1
    }
}
