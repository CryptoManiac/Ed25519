using System;
using Chaos.NaCl.Internal.Ed25519Ref10;
using System.Diagnostics.Contracts;

namespace Chaos.NaCl
{
    public static class Ed25519
    {
        public static readonly int PublicKeySize = 32;
        public static readonly int SignatureSize = 64;
        public static readonly int ExpandedPrivateKeySize = 32 * 2;
        public static readonly int PrivateKeySeedSize = 32;

        public static bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> publicKey)
        {
            Contract.Requires<ArgumentException>(signature.Count == SignatureSize && publicKey.Count == PublicKeySize);

            return Ed25519Operations.crypto_sign_verify(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, publicKey.Array, publicKey.Offset);
        }

        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            Contract.Requires<ArgumentNullException>(signature != null && message != null && publicKey != null);
            Contract.Requires<ArgumentException>(signature.Length == SignatureSize && publicKey.Length == PublicKeySize);

            return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
        }

        public static void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> expandedPrivateKey)
        {
            Contract.Requires<ArgumentNullException>(signature.Array != null && message.Array != null && expandedPrivateKey.Array != null);
            Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize);

            Ed25519Operations.crypto_sign(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, expandedPrivateKey.Array, expandedPrivateKey.Offset);
        }

        public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
        {
            var signature = new byte[SignatureSize];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(privateKey);
            return publicKey;
        }

        public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(publicKey);
            return privateKey;
        }

        public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
        {
            Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);

            var pk = new byte[PublicKeySize];
            var sk = new byte[ExpandedPrivateKeySize];

            Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);
            publicKey = pk;
            expandedPrivateKey = sk;
        }

        public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey, ArraySegment<byte> privateKeySeed)
        {
            Contract.Requires<ArgumentNullException>(publicKey.Array != null && expandedPrivateKey.Array != null && privateKeySeed.Array != null);
            Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize && privateKeySeed.Count == PrivateKeySeedSize);
            Contract.Requires<ArgumentException>(publicKey.Count == PublicKeySize);

            Ed25519Operations.crypto_sign_keypair(
                publicKey.Array, publicKey.Offset,
                expandedPrivateKey.Array, expandedPrivateKey.Offset,
                privateKeySeed.Array, privateKeySeed.Offset);
        }
    }
}