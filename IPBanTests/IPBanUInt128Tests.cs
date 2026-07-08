/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for the custom UInt128 struct used as the IPv6 numeric backing for
IPAddressRange. Bugs in arithmetic, comparison, or BigInteger round-trip would
silently break v6 range matching across the codebase.
*/

using System.Numerics;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanUInt128Tests
    {
        // -------------------- constants and constructors --------------------

        [Test]
        public void Constants_HaveExpectedValues()
        {
            ClassicAssert.AreEqual(0UL, UInt128.Zero.LeastSignificant);
            ClassicAssert.AreEqual(0UL, UInt128.Zero.MostSignificant);

            ClassicAssert.AreEqual(1UL, UInt128.One.LeastSignificant);
            ClassicAssert.AreEqual(0UL, UInt128.One.MostSignificant);

            ClassicAssert.AreEqual(0UL, UInt128.MinValue.LeastSignificant);
            ClassicAssert.AreEqual(0UL, UInt128.MinValue.MostSignificant);

            ClassicAssert.AreEqual(ulong.MaxValue, UInt128.MaxValue.LeastSignificant);
            ClassicAssert.AreEqual(ulong.MaxValue, UInt128.MaxValue.MostSignificant);
        }

        [Test]
        public void Construct_FromTwoLongs_StoresAsExpected()
        {
            var v = new UInt128(0x1234_5678_9ABC_DEF0UL, 0x0FED_CBA9_8765_4321UL);
            ClassicAssert.AreEqual(0x1234_5678_9ABC_DEF0UL, v.MostSignificant);
            ClassicAssert.AreEqual(0x0FED_CBA9_8765_4321UL, v.LeastSignificant);
        }

        [Test]
        public void Construct_FromUlong_LeavesUpperZero()
        {
            UInt128 v = 42UL;   // implicit conversion
            ClassicAssert.AreEqual(42UL, v.LeastSignificant);
            ClassicAssert.AreEqual(0UL, v.MostSignificant);
        }

        // -------------------- BigInteger round-trip --------------------

        [Test]
        public void BigInteger_RoundTrips_AcrossSignificantValues()
        {
            BigInteger[] cases =
            {
                BigInteger.Zero,
                BigInteger.One,
                42,
                ulong.MaxValue,                                            // exactly 64 bits
                BigInteger.Pow(2, 64),                                     // first value needing the upper word
                BigInteger.Pow(2, 64) + 1,
                BigInteger.Pow(2, 127),                                    // top bit set
                (BigInteger.One << 128) - 1,                               // UInt128.MaxValue
            };

            foreach (var bi in cases)
            {
                UInt128 v = (UInt128)bi;
                BigInteger back = v;   // implicit conversion via operator
                ClassicAssert.AreEqual(bi, back, $"round-trip failed for {bi}");
            }
        }

        // -------------------- equality + comparison --------------------

        [Test]
        public void Equality_TwoIdenticalValuesAreEqual()
        {
            var a = new UInt128(7, 11);
            var b = new UInt128(7, 11);

            ClassicAssert.IsTrue(a == b);
            ClassicAssert.IsFalse(a != b);
            ClassicAssert.IsTrue(a.Equals(b));
            ClassicAssert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [Test]
        public void Equality_DifferentMostSignificantNotEqual()
        {
            ClassicAssert.IsFalse(new UInt128(1, 0) == new UInt128(2, 0));
        }

        [Test]
        public void Equality_DifferentLeastSignificantNotEqual()
        {
            ClassicAssert.IsFalse(new UInt128(0, 1) == new UInt128(0, 2));
        }

        [Test]
        public void Comparison_OrderMatchesNumericValue()
        {
            // a < b < c — verify each comparison operator agrees.
            UInt128 a = 1UL;
            UInt128 b = ulong.MaxValue;                 // 2^64 - 1
            UInt128 c = new(1UL, 0UL);                  // 2^64

            // Use a copy for the reflexive checks so the compiler doesn't complain about
            // self-comparison (CS1718). Semantically identical — verifies <= / >= return true
            // for two equal values.
            UInt128 aCopy = 1UL;
            UInt128 cCopy = new(1UL, 0UL);

            ClassicAssert.IsTrue(a < b); ClassicAssert.IsTrue(b < c);
            ClassicAssert.IsTrue(c > b); ClassicAssert.IsTrue(b > a);
            ClassicAssert.IsTrue(a <= aCopy); ClassicAssert.IsTrue(a <= b);
            ClassicAssert.IsTrue(c >= cCopy); ClassicAssert.IsTrue(c >= b);

            ClassicAssert.AreEqual(-1, a.CompareTo(b));
            ClassicAssert.AreEqual( 1, c.CompareTo(b));
            ClassicAssert.AreEqual( 0, b.CompareTo(b));
        }

        [Test]
        public void Comparison_AcrossUpperWordBoundary()
        {
            // Two values where MSB differs by 1; the bigger must compare greater regardless of
            // LSB ordering — confirms the comparator orders MSB-then-LSB, not LSB-only.
            UInt128 a = new(1UL, ulong.MaxValue);
            UInt128 b = new(2UL, 0UL);
            ClassicAssert.IsTrue(b > a);
        }

        // -------------------- arithmetic --------------------

        [Test]
        public void Add_SimpleSumWithinLowerWord()
        {
            UInt128 a = 100UL;
            UInt128 b = 23UL;
            ClassicAssert.AreEqual((UInt128)123UL, a + b);
        }

        [Test]
        public void Add_CarryFromLowerToUpperWord()
        {
            // 0xFFFF_FFFF_FFFF_FFFF + 1 should produce a carry into the upper word.
            UInt128 v = ulong.MaxValue;
            UInt128 result = v + 1UL;
            ClassicAssert.AreEqual(0UL, result.LeastSignificant);
            ClassicAssert.AreEqual(1UL, result.MostSignificant);
        }

        [Test]
        public void Add_OverflowWrapsAroundLikeNativeUnsigned()
        {
            // MaxValue + 1 wraps to 0 (modular semantics for unsigned 128-bit).
            UInt128 result = UInt128.MaxValue + UInt128.One;
            ClassicAssert.AreEqual(UInt128.Zero, result);
        }

        [Test]
        public void Subtract_SimpleDifferenceWithinLowerWord()
        {
            ClassicAssert.AreEqual((UInt128)77UL, (UInt128)100UL - (UInt128)23UL);
        }

        [Test]
        public void Subtract_BorrowFromUpperWord()
        {
            // (1, 0) - 1 = (0, 0xFFFF_FFFF_FFFF_FFFF)
            UInt128 result = new UInt128(1UL, 0UL) - 1UL;
            ClassicAssert.AreEqual(0UL, result.MostSignificant);
            ClassicAssert.AreEqual(ulong.MaxValue, result.LeastSignificant);
        }

        [Test]
        public void Subtract_UnderflowWrapsAroundLikeNativeUnsigned()
        {
            // 0 - 1 wraps to MaxValue.
            UInt128 result = UInt128.Zero - UInt128.One;
            ClassicAssert.AreEqual(UInt128.MaxValue, result);
        }

        // -------------------- bitwise --------------------

        [Test]
        public void BitwiseAnd_MasksAcrossBothWords()
        {
            UInt128 a = new(0xFFFF_0000_FFFF_0000UL, 0xFFFF_0000_FFFF_0000UL);
            UInt128 b = new(0x0000_FFFF_0000_FFFFUL, 0x0F0F_0F0F_0F0F_0F0FUL);
            UInt128 r = a & b;
            ClassicAssert.AreEqual(0x0000_0000_0000_0000UL, r.MostSignificant);
            ClassicAssert.AreEqual(0x0F0F_0000_0F0F_0000UL, r.LeastSignificant);
        }

        [Test]
        public void BitwiseOr_UnionsBothWords()
        {
            UInt128 a = new(0xAAAA_AAAA_AAAA_AAAAUL, 0x5555_5555_5555_5555UL);
            UInt128 b = new(0x5555_5555_5555_5555UL, 0xAAAA_AAAA_AAAA_AAAAUL);
            UInt128 r = a | b;
            ClassicAssert.AreEqual(ulong.MaxValue, r.MostSignificant);
            ClassicAssert.AreEqual(ulong.MaxValue, r.LeastSignificant);
        }

        [Test]
        public void LeftShift_WithinLowerWord()
        {
            UInt128 v = 1UL;
            UInt128 r = v << 4;
            ClassicAssert.AreEqual(16UL, r.LeastSignificant);
            ClassicAssert.AreEqual(0UL, r.MostSignificant);
        }

        [Test]
        public void LeftShift_AcrossWordBoundary()
        {
            // 1 << 64 should land entirely in the upper word.
            UInt128 r = (UInt128)1UL << 64;
            ClassicAssert.AreEqual(0UL, r.LeastSignificant);
            ClassicAssert.AreEqual(1UL, r.MostSignificant);
        }

        [Test]
        public void RightShift_AcrossWordBoundary()
        {
            // High bit (1 << 64) shifted right by 64 returns to the lower word.
            UInt128 v = new(1UL, 0UL);
            UInt128 r = v >> 64;
            ClassicAssert.AreEqual(1UL, r.LeastSignificant);
            ClassicAssert.AreEqual(0UL, r.MostSignificant);
        }

        // -------------------- parsing and formatting --------------------

        [Test]
        public void Parse_DecimalRoundTrip()
        {
            // Pick a value that uses both 64-bit words.
            BigInteger expected = (BigInteger.One << 100) + 12345;
            UInt128 v = (UInt128)expected;

            string s = v.ToString();
            ClassicAssert.AreEqual(expected.ToString(), s);

            UInt128 back = UInt128.Parse(s);
            ClassicAssert.AreEqual(v, back);
        }

        [Test]
        public void Parse_MaxValueRoundTrip()
        {
            string s = UInt128.MaxValue.ToString();
            ClassicAssert.AreEqual(UInt128.MaxValue, UInt128.Parse(s));
        }

        [Test]
        public void Parse_ZeroRoundTrip()
        {
            ClassicAssert.AreEqual(UInt128.Zero, UInt128.Parse("0"));
            ClassicAssert.AreEqual("0", UInt128.Zero.ToString());
        }

        [Test]
        public void TryParse_RejectsGarbage()
        {
            ClassicAssert.IsFalse(UInt128.TryParse("not-a-number", out _));
            ClassicAssert.IsFalse(UInt128.TryParse(string.Empty, out _));
            ClassicAssert.IsFalse(UInt128.TryParse(null, out _));
        }

        [Test]
        public void TryParse_AcceptsNormalInput()
        {
            ClassicAssert.IsTrue(UInt128.TryParse("123456789", out var v));
            ClassicAssert.AreEqual((UInt128)123456789UL, v);
        }

        // -------------------- explicit conversions --------------------

        [Test]
        public void ExplicitToUlong_TruncatesUpperBits()
        {
            // (1, 42) → cast to ulong returns the low 64 bits (42), upper bits are dropped.
            UInt128 v = new(1UL, 42UL);
            ClassicAssert.AreEqual(42UL, (ulong)v);
        }
    }
}
