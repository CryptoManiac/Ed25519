using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    public class Ed25519Tests
    {
        [AssemblyInitializeAttribute]
        public static void LoadTestVectors(TestContext context)
        {
            Ed25519TestVectors.LoadTestCases();
            //Warmup
            var pk = Ed25519.PublicKeyFromSeed(new byte[32]);
            var sk = Ed25519.ExpandedPrivateKeyFromSeed(new byte[32]);
            var sig = Ed25519.Sign(Ed25519TestVectors.TestCases.Last().getMessage(), sk);
            Ed25519.Verify(sig, new byte[10], pk);
        }

        [TestMethod]
        public void KeyPairFromSeed()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                byte[] publicKey;
                byte[] privateKey;
                Ed25519.KeyPairFromSeed(out publicKey, out privateKey, testCase.getSeed());
                TestHelpers.AssertEqualBytes(testCase.getPublicKey(), publicKey);
                TestHelpers.AssertEqualBytes(testCase.getPrivateKey(), privateKey);
            }
        }


        [TestMethod]
        public void KeyPairFromSeedSegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var publicKey = new byte[Ed25519.PublicKeySize].Pad();
                var privateKey = new byte[Ed25519.ExpandedPrivateKeySize].Pad();
                Ed25519.KeyPairFromSeed(publicKey, privateKey, testCase.getSeed().Pad());
                TestHelpers.AssertEqualBytes(testCase.getPublicKey(), publicKey.UnPad());
                TestHelpers.AssertEqualBytes(testCase.getPrivateKey(), privateKey.UnPad());
            }
        }

        [TestMethod]
        public void Sign()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                var sig = Ed25519.Sign(testCase.getMessage(), testCase.getPrivateKey());
                Assert.AreEqual(64, sig.Length);
                TestHelpers.AssertEqualBytes(testCase.getSignature(), sig);
            }
        }

        [TestMethod]
        public void Verify()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                bool success = Ed25519.Verify(testCase.getSignature(), testCase.getMessage(), testCase.getPublicKey());
                Assert.IsTrue(success);
            }
        }

        [TestMethod]
        public void VerifyFail()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature, message, pk));
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(signature, modifiedMessage, pk));
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(modifiedSignature, message, pk));
            }
        }

        private byte[] AddL(IEnumerable<byte> input)
        {
            var signedInput = input.Concat(new byte[] { 0 }).ToArray();
            var i = new BigInteger(signedInput);
            var l = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
            i += l;
            var result = i.ToByteArray().Concat(Enumerable.Repeat((byte)0, 32)).Take(32).ToArray();
            return result;
        }

        private byte[] AddLToSignature(byte[] signature)
        {
            return signature.Take(32).Concat(AddL(signature.Skip(32))).ToArray();
        }

        // Ed25519 is malleable in the `S` part of the signature
        // One can add (a multiple of) the order of the subgroup `l` to `S` without invalidating the signature
        // The implementation only checks if the 3 high bits are zero, which is equivalent to checking if S < 2^253
        // since `l` is only slightly larger than 2^252 this means that you can add `l` to almost every signature
        // *once* without violating this condition, adding it twice will exceed 2^253 causing the signature to be rejected
        // This test serves to document the *is* behaviour, and doesn't define *should* behaviour
        //
        // I consider rejecting signatures with S >= l, but should probably talk to upstream and libsodium before that
        [TestMethod]
        public void MalleabilityAddL()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature, message, pk));
            var modifiedSignature = AddLToSignature(signature);
            Assert.IsTrue(Ed25519.Verify(modifiedSignature, message, pk));
            var modifiedSignature2 = AddLToSignature(modifiedSignature);
            Assert.IsFalse(Ed25519.Verify(modifiedSignature2, message, pk));
        }

        [TestMethod]
        public void VerifySegments()
        {
            foreach (var testCase in Ed25519TestVectors.TestCases)
            {
                bool success = Ed25519.Verify(testCase.getSignature().Pad(), testCase.getMessage().Pad(), testCase.getPublicKey().Pad());
                Assert.IsTrue(success);
            }
        }

        [TestMethod]
        public void VerifyFailSegments()
        {
            var message = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
            byte[] pk;
            byte[] sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, new byte[32]);
            var signature = Ed25519.Sign(message, sk);
            Assert.IsTrue(Ed25519.Verify(signature.Pad(), message.Pad(), pk.Pad()));
            foreach (var modifiedMessage in message.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(signature.Pad(), modifiedMessage.Pad(), pk.Pad()));
            }
            foreach (var modifiedSignature in signature.WithChangedBit())
            {
                Assert.IsFalse(Ed25519.Verify(modifiedSignature.Pad(), message.Pad(), pk.Pad()));
            }
        }
    }
}
