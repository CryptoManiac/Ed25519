`Ed25519` (Key-exchange and signatures)
===========================

Ed25519 is a public key crypto system with a 128 bit security level.
It is based on the 255 bit elliptic curve Curve25519 using Edwards coordinates.

Data structures
---------------

* *Public Keys* are 32 byte values. Any possible value of this size represents a valid public key.
* *Private Keys* can be represented in two forms:

    * A 32 byte seeds which allow arbitrary values. This is the form that should be generated and stored.
    * A 64 byte expanded form. This form is used internally to improve performance

* *Signatures* are 64 byte values

To generate a keypair first obtain a 32 byte random value, the `privateKeySeed`
from a cryptographic random number generator, such as `RNGCryptoService`.

Then call `KeyPairFromSeed` on it to get the `publicKey` and the `expandedPrivateKey`.

API
---

    public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)

Returns the 32 byte public key corresponding the given `privateKeySeed`.

    public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)

Expands the `privateKeySeed` into the form used by the `Sign` function.

    public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)

Equivalent to calling both `PublicKeyFromSeed` and `ExpandedPrivateKeyFromSeed`.

Using this function is twice as fast as calling them individually.

    public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)

Returns the 64 byte signature for `message` using the given private key. The signature
can be verified using `Verify` with the corresponding public key.

    public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)

Verifies if `signature` was produced by signing `message` using the private key
corresponding to `publicKey`.

Returns `true` if the signature is valid, `false` if it is not.

    public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)

Returns a secred shared by the owners of the two keys pairs. This key can be used
with symmetric cryptography, such as encryption, MACs and authenticated encryption.

This uses Edwards form public keys, but is otherwise identical to `MontgomeryCurve25519.KeyExchange`.
The advantage of this method is that you can use one keypair for both key-exchange and signing.

Performance
-----------

On a single core of my Intel Core i3 M390 with 2.66 GHz I obtain:

    Key generation:             116.68 us / 8571 per second / 310356 cycles
    Signing a short message:    122.46 us / 8166 per second / 325746 cycles
    Verifying a short message:  279.18 us / 3582 per second / 742607 cycles

This is about 1.4 times as slow as the equivalent c code.

CryptoBytes
===========

Contains helper functions commonly used in cryptographic code.

    void Wipe(byte[] data)

Overwrites the contents of the array, wiping the previous content. This should be used
to destroy cryptographic secrets that are no longer required.

Complicating factors like swap files, crash dumps and the moving garbage collector
reduce the reliability of this function.

    public static bool ConstantTimeEquals(byte[] x, byte[] y)

Checks if the contents of the two arrays are the same and returns `true` if they are equal.  

The runtime of this method does not depend on the contents of the arrays. Using constant time
prevents timing attacks that allow an attacker to learn if the arrays have a common prefix.
It is important to use such a constant time comparison when verifying MACs.

    public static string ToHexString(byte[] data)

Converts the bytes to an upper-case hex string.

*constant time*

    public static string ToHexStringLower(byte[] data)

Converts the bytes to a lower-case hex string.

*constant time*

    public static byte[] FromHexString(string hexString)

Converts the hex string to bytes. Case insensitive.

*variable time*

    public static string ToBase64String(byte[] data)

Encodes the bytes with the Base64 encoding. More compact than hex, but it is case-sensitive
and uses the special characters `+`, `/` and `=`.

*variable time*

    public static byte[] FromBase64String(string s)

Decodes a Base64 encoded string back to bytes.

*variable time*
