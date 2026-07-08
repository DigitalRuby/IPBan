/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPV6Range struct.
*/

using System;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using UInt128 = DigitalRuby.IPBanCore.UInt128;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanIPV6RangeTests
    {
        [Test]
        public void Construct_FromIPAddressRange()
        {
            var range = IPAddressRange.Parse("::1-::ff");
            var v6 = new IPV6Range(range);
            ClassicAssert.AreEqual(range.Begin.ToUInt128(), v6.Begin);
            ClassicAssert.AreEqual(range.End.ToUInt128(), v6.End);
        }

        [Test]
        public void Construct_FromIPAddressRange_ThrowsForIPv4()
        {
            var range = IPAddressRange.Parse("1.2.3.4");
            Assert.Throws<InvalidOperationException>(() => new IPV6Range(range));
        }

        [Test]
        public void Construct_FromSingle()
        {
            UInt128 single = new(123, 456);
            var v6 = new IPV6Range(single);
            ClassicAssert.AreEqual(single, v6.Begin);
            ClassicAssert.AreEqual(single, v6.End);
        }

        [Test]
        public void Equals_ComparesByValue()
        {
            UInt128 a = new(1, 0), b = new(2, 0), c = new(3, 0);
            ClassicAssert.IsTrue(new IPV6Range(a, b) == new IPV6Range(a, b));
            ClassicAssert.IsTrue(new IPV6Range(a, b) != new IPV6Range(a, c));
            ClassicAssert.IsTrue(new IPV6Range(a, b).Equals((object)new IPV6Range(a, b)));
            ClassicAssert.IsFalse(new IPV6Range(a, b).Equals("not a range"));
            ClassicAssert.AreEqual(new IPV6Range(a, b).GetHashCode(), new IPV6Range(a, b).GetHashCode());
        }

        [Test]
        public void ToString_FormatsAsRange()
        {
            var range = IPAddressRange.Parse("::1-::ff");
            var v6 = new IPV6Range(range);
            ClassicAssert.IsNotNull(v6.ToString());
        }

        [Test]
        public void ToIPAddressRange_RoundTrips()
        {
            var range = IPAddressRange.Parse("::1-::ff");
            var v6 = new IPV6Range(range);
            var roundTripped = v6.ToIPAddressRange();
            ClassicAssert.AreEqual(range.Begin, roundTripped.Begin);
            ClassicAssert.AreEqual(range.End, roundTripped.End);
        }

        [Test]
        public void CompareTo_DisjointRanges()
        {
            var a = new IPV6Range(new UInt128(1, 0), new UInt128(10, 0));
            var b = new IPV6Range(new UInt128(20, 0), new UInt128(30, 0));
            ClassicAssert.IsTrue(a.CompareTo(b) < 0);
            ClassicAssert.IsTrue(b.CompareTo(a) > 0);
            ClassicAssert.AreEqual(0, new IPV6Range(new UInt128(1, 0), new UInt128(10, 0)).CompareTo(
                new IPV6Range(new UInt128(5, 0), new UInt128(15, 0))));
        }
    }
}
