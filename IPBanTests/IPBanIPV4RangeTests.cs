/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPV4Range struct.
*/

using System;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanIPV4RangeTests
    {
        [Test]
        public void Construct_FromIPAddressRange()
        {
            var range = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            var v4 = new IPV4Range(range);
            ClassicAssert.AreEqual(range.Begin.ToUInt32(), v4.Begin);
            ClassicAssert.AreEqual(range.End.ToUInt32(), v4.End);
        }

        [Test]
        public void Construct_FromIPAddressRange_ThrowsForIPv6()
        {
            var range = IPAddressRange.Parse("::1");
            Assert.Throws<InvalidOperationException>(() => new IPV4Range(range));
        }

        [Test]
        public void Construct_FromSingle()
        {
            var v4 = new IPV4Range(123u);
            ClassicAssert.AreEqual(123u, v4.Begin);
            ClassicAssert.AreEqual(123u, v4.End);
        }

        [Test]
        public void Equals_ComparesByValue()
        {
            ClassicAssert.IsTrue(new IPV4Range(1, 2) == new IPV4Range(1, 2));
            ClassicAssert.IsTrue(new IPV4Range(1, 2) != new IPV4Range(1, 3));
            ClassicAssert.IsTrue(new IPV4Range(1, 2).Equals((object)new IPV4Range(1, 2)));
            ClassicAssert.IsFalse(new IPV4Range(1, 2).Equals("not a range"));
            ClassicAssert.AreEqual(new IPV4Range(1, 2).GetHashCode(), new IPV4Range(1, 2).GetHashCode());
        }

        [Test]
        public void ToString_FormatsAsRange()
        {
            var range = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            var v4 = new IPV4Range(range);
            string s = v4.ToString();
            StringAssert.Contains("1.2.3.4", s);
            StringAssert.Contains("1.2.3.10", s);
        }

        [Test]
        public void ToIPAddressRange_RoundTrips()
        {
            var range = IPAddressRange.Parse("10.0.0.0-10.255.255.255");
            var v4 = new IPV4Range(range);
            var roundTripped = v4.ToIPAddressRange();
            ClassicAssert.AreEqual(range.Begin, roundTripped.Begin);
            ClassicAssert.AreEqual(range.End, roundTripped.End);
        }

        [Test]
        public void CompareTo_DisjointRanges()
        {
            var a = new IPV4Range(1, 10);
            var b = new IPV4Range(20, 30);
            ClassicAssert.IsTrue(a.CompareTo(b) < 0);
            ClassicAssert.IsTrue(b.CompareTo(a) > 0);
            ClassicAssert.AreEqual(0, new IPV4Range(1, 10).CompareTo(new IPV4Range(5, 15)));
        }
    }
}
