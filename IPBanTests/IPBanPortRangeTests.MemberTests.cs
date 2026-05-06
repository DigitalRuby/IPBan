/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Member-level coverage for PortRange — constructors, IsValid, Equals/HashCode,
ToString, parsing, ordering, JSON conversion. Complements the firewall-flow
tests in IPBanPortRangeTests.cs.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    public partial class IPBanPortRangeTests
    {
        [Test]
        public void Construct_SinglePort_MinAndMaxEqual()
        {
            var pr = new PortRange(80);
            ClassicAssert.AreEqual(80, pr.MinPort);
            ClassicAssert.AreEqual(80, pr.MaxPort);
            ClassicAssert.IsTrue(pr.IsValid);
        }

        [Test]
        public void Construct_PortRange_StoresMinAndMax()
        {
            var pr = new PortRange(80, 100);
            ClassicAssert.AreEqual(80, pr.MinPort);
            ClassicAssert.AreEqual(100, pr.MaxPort);
            ClassicAssert.IsTrue(pr.IsValid);
        }

        [Test]
        public void IsValid_ReturnsFalseForInvalidRanges()
        {
            ClassicAssert.IsFalse(new PortRange(-1).IsValid);
            ClassicAssert.IsFalse(new PortRange(80, 70).IsValid);
            ClassicAssert.IsFalse(new PortRange(70000).IsValid);
            ClassicAssert.IsFalse(new PortRange(-5, -1).IsValid);
        }

        [Test]
        public void Equals_PortRanges_ComparesByValue()
        {
            ClassicAssert.IsTrue(new PortRange(80) == new PortRange(80));
            ClassicAssert.IsTrue(new PortRange(80, 90) == new PortRange(80, 90));
            ClassicAssert.IsFalse(new PortRange(80) == new PortRange(81));
            ClassicAssert.IsTrue(new PortRange(80) != new PortRange(81));
            ClassicAssert.IsTrue(new PortRange(80).Equals((object)new PortRange(80)));
            ClassicAssert.IsFalse(new PortRange(80).Equals("not a range"));
            ClassicAssert.AreEqual(new PortRange(80).GetHashCode(), new PortRange(80).GetHashCode());
        }

        [Test]
        public void ToString_FormatsByRangeShape()
        {
            ClassicAssert.AreEqual("80", new PortRange(80).ToString());
            ClassicAssert.AreEqual("80-100", new PortRange(80, 100).ToString());
            ClassicAssert.IsNull(new PortRange(70000).ToString());
            ClassicAssert.IsNull(new PortRange(80, 70).ToString());
        }

        [Test]
        public void ImplicitOperators_StringRoundTrip()
        {
            string s = (string)new PortRange(80, 90);
            ClassicAssert.AreEqual("80-90", s);
            PortRange pr = "80-90";
            ClassicAssert.AreEqual(80, pr.MinPort);
            ClassicAssert.AreEqual(90, pr.MaxPort);
        }

        [Test]
        public void Contains_PortInRange_ReturnsTrue()
        {
            var pr = new PortRange(80, 90);
            ClassicAssert.IsTrue(pr.Contains(80));
            ClassicAssert.IsTrue(pr.Contains(85));
            ClassicAssert.IsTrue(pr.Contains(90));
            ClassicAssert.IsFalse(pr.Contains(79));
            ClassicAssert.IsFalse(pr.Contains(91));
        }

        [Test]
        public void Parse_ValidStrings_ReturnsCorrectRange()
        {
            ClassicAssert.AreEqual(new PortRange(80), PortRange.Parse("80"));
            ClassicAssert.AreEqual(new PortRange(80, 100), PortRange.Parse("80-100"));
            ClassicAssert.AreEqual(new PortRange(80, 100), PortRange.Parse(" 80-100 "));
        }

        [Test]
        public void Parse_InvalidStrings_ReturnsInvalidRange()
        {
            ClassicAssert.IsFalse(PortRange.Parse("").IsValid);
            ClassicAssert.IsFalse(PortRange.Parse(null).IsValid);
            ClassicAssert.IsFalse(PortRange.Parse("-5").IsValid);
            ClassicAssert.IsFalse(PortRange.Parse("not-a-port").IsValid);
            ClassicAssert.IsFalse(PortRange.Parse("80-90-100").IsValid);
        }

        [Test]
        public void ParseRanges_CommaSeparated_ReturnsArray()
        {
            var ranges = PortRange.ParseRanges("80,443,1000-2000");
            ClassicAssert.AreEqual(3, ranges.Length);
            ClassicAssert.AreEqual(new PortRange(80), ranges[0]);
            ClassicAssert.AreEqual(new PortRange(443), ranges[1]);
            ClassicAssert.AreEqual(new PortRange(1000, 2000), ranges[2]);
        }

        [Test]
        public void ParseRanges_EmptyOrInvalid_FiltersOut()
        {
            CollectionAssert.IsEmpty(PortRange.ParseRanges(""));
            CollectionAssert.IsEmpty(PortRange.ParseRanges(null));
            var ranges = PortRange.ParseRanges("80,garbage,443");
            ClassicAssert.AreEqual(2, ranges.Length);
        }

        [Test]
        public void CompareTo_OrdersByMinThenMax()
        {
            ClassicAssert.IsTrue(new PortRange(80).CompareTo(new PortRange(81)) < 0);
            ClassicAssert.IsTrue(new PortRange(81).CompareTo(new PortRange(80)) > 0);
            ClassicAssert.IsTrue(new PortRange(80, 90).CompareTo(new PortRange(80, 100)) < 0);
            ClassicAssert.IsTrue(new PortRange(80, 100).CompareTo(new PortRange(80, 90)) > 0);
            ClassicAssert.IsTrue(new PortRange(80, 90).CompareTo(new PortRange(80, 90)) == 0);
            ClassicAssert.IsTrue(new PortRange(80) < new PortRange(81));
            ClassicAssert.IsTrue(new PortRange(80) <= new PortRange(80));
            ClassicAssert.IsTrue(new PortRange(81) > new PortRange(80));
            ClassicAssert.IsTrue(new PortRange(81) >= new PortRange(81));
        }

        [Test]
        public void JsonRoundTrip_UsesStringForm()
        {
            var pr = new PortRange(80, 100);
            string json = System.Text.Json.JsonSerializer.Serialize(pr);
            ClassicAssert.AreEqual("\"80-100\"", json);
            var back = System.Text.Json.JsonSerializer.Deserialize<PortRange>(json);
            ClassicAssert.AreEqual(pr, back);
        }
    }
}
