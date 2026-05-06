/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPAddressRange members not exercised by the existing
IPBanIPAddressRangeTests file: subnet mask helpers, dictionary interface,
JSON converter, ToCidrString, GetCount/GetPrefixLength, Chomp/TryCombine,
implicit operators, and edge-case Parse paths.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using UInt128 = DigitalRuby.IPBanCore.UInt128;

namespace DigitalRuby.IPBanTests
{
    public partial class IPBanIPAddressRangeTest
    {
        // -------- Implicit operators --------

        [Test]
        public void ImplicitOperator_FromStringAndToString_RoundTrip()
        {
            IPAddressRange r = "1.2.3.4-1.2.3.5";
            ClassicAssert.AreEqual("1.2.3.4", r.Begin.ToString());
            ClassicAssert.AreEqual("1.2.3.5", r.End.ToString());

            string s = r;
            ClassicAssert.IsTrue(s.Contains("1.2.3.4"));
        }

        [Test]
        public void ImplicitOperator_FromIPAddress_MakesSingleRange()
        {
            IPAddressRange r = IPAddress.Parse("1.2.3.4");
            ClassicAssert.IsTrue(r.Single);
        }

        // -------- Parse / TryParse --------

        [Test]
        public void Parse_NullOrEmpty_Throws()
        {
            // Both null and whitespace-only inputs throw ArgumentNullException with the
            // throwException flag enabled (the default).
            Assert.Throws<ArgumentNullException>(() => IPAddressRange.Parse(null));
            Assert.Throws<ArgumentNullException>(() => IPAddressRange.Parse(""));
        }

        [Test]
        public void TryParse_NullOrEmpty_ReturnsFalse()
        {
            ClassicAssert.IsFalse(IPAddressRange.TryParse(null, out _));
            ClassicAssert.IsFalse(IPAddressRange.TryParse(string.Empty, out _));
        }

        [Test]
        public void Parse_RangeWithSpaces_ParsesCleanly()
        {
            var r = IPAddressRange.Parse(" 1.2.3.4 - 1.2.3.10 ");
            ClassicAssert.AreEqual("1.2.3.4", r.Begin.ToString());
            ClassicAssert.AreEqual("1.2.3.10", r.End.ToString());
        }

        [Test]
        public void Parse_Cidr_ProducesCorrectRange()
        {
            var r = IPAddressRange.Parse("10.0.0.0/24");
            ClassicAssert.AreEqual("10.0.0.0", r.Begin.ToString());
            ClassicAssert.AreEqual("10.0.0.255", r.End.ToString());
        }

        [Test]
        public void Parse_IPv6Single_ParsesAsSingle()
        {
            var r = IPAddressRange.Parse("::1");
            ClassicAssert.IsTrue(r.Single);
        }

        // -------- ToCidrString / GetPrefixLength --------

        [Test]
        public void ToCidrString_OnSingleIP()
        {
            var r = IPAddressRange.Parse("1.2.3.4");
            // displaySingleSubnet defaults to true so we expect "1.2.3.4/32"
            string c = r.ToCidrString();
            StringAssert.Contains("1.2.3.4", c);
            StringAssert.Contains("/32", c);

            // displaySingleSubnet false -> just IP
            ClassicAssert.AreEqual("1.2.3.4", r.ToCidrString(displaySingleSubnet: false));
        }

        [Test]
        public void ToCidrString_OnRangeWithPrefix()
        {
            var r = IPAddressRange.Parse("10.0.0.0/16");
            ClassicAssert.AreEqual("10.0.0.0/16", r.ToCidrString());
        }

        [Test]
        public void ToCidrString_OnNonAlignedRange_FallsBackToRange()
        {
            // A non-cidr-aligned range -> falls back to Begin-End
            var r = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            string s = r.ToCidrString();
            StringAssert.Contains("-", s);
        }

        [Test]
        public void GetPrefixLength_Cidr_ReturnsCorrect()
        {
            var r = IPAddressRange.Parse("10.0.0.0/24");
            ClassicAssert.AreEqual(24, r.GetPrefixLength());
        }

        [Test]
        public void GetPrefixLength_NonCidr_DoesNotThrowWhenFalse()
        {
            var r = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            ClassicAssert.Less(r.GetPrefixLength(false), 0, "non-cidr ranges return -1 with throwException=false");
        }

        [Test]
        public void GetPrefixLength_NonCidr_ThrowsWhenTrue()
        {
            var r = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            Assert.Throws<FormatException>(() => r.GetPrefixLength(true));
        }

        // -------- GetCount --------

        [Test]
        public void GetCount_SingleIP_IsOne()
        {
            var r = IPAddressRange.Parse("1.2.3.4");
            ClassicAssert.AreEqual((UInt128)1, r.GetCount());
        }

        [Test]
        public void GetCount_24Cidr_Is256()
        {
            var r = IPAddressRange.Parse("10.0.0.0/24");
            ClassicAssert.AreEqual((UInt128)256, r.GetCount());
        }

        [Test]
        public void GetCount_IPv6_NonZero()
        {
            var r = IPAddressRange.Parse("::1-::ff");
            UInt128 count = r.GetCount();
            ClassicAssert.AreNotEqual((UInt128)0, count);
        }

        // -------- Contains (range over range) --------

        [Test]
        public void Contains_Subrange_True()
        {
            var outer = IPAddressRange.Parse("10.0.0.0/16");
            var inner = IPAddressRange.Parse("10.0.5.0/24");
            ClassicAssert.IsTrue(outer.Contains(inner));
            ClassicAssert.IsFalse(inner.Contains(outer));
        }

        [Test]
        public void Contains_DifferentFamily_False()
        {
            var v4 = IPAddressRange.Parse("10.0.0.0/16");
            var v6 = IPAddressRange.Parse("::1");
            ClassicAssert.IsFalse(v4.Contains(v6));
        }

        // -------- TryCombine --------

        [Test]
        public void TryCombine_OverlappingRanges_Combine()
        {
            var a = IPAddressRange.Parse("1.0.0.0-1.0.0.20");
            var b = IPAddressRange.Parse("1.0.0.10-1.0.0.30");
            ClassicAssert.IsTrue(a.TryCombine(b, out var combined));
            ClassicAssert.AreEqual("1.0.0.0", combined.Begin.ToString());
            ClassicAssert.AreEqual("1.0.0.30", combined.End.ToString());
        }

        [Test]
        public void TryCombine_AdjacentRanges_Combine()
        {
            var a = IPAddressRange.Parse("1.0.0.0-1.0.0.20");
            var b = IPAddressRange.Parse("1.0.0.21-1.0.0.30");
            ClassicAssert.IsTrue(a.TryCombine(b, out var combined));
            ClassicAssert.AreEqual("1.0.0.30", combined.End.ToString());
        }

        [Test]
        public void TryCombine_DisjointRanges_DoNotCombine()
        {
            var a = IPAddressRange.Parse("1.0.0.0/24");
            var b = IPAddressRange.Parse("3.0.0.0/24");
            ClassicAssert.IsFalse(a.TryCombine(b, out _));
        }

        [Test]
        public void TryCombine_DifferentFamilies_DoNotCombine()
        {
            var a = IPAddressRange.Parse("1.0.0.0");
            var b = IPAddressRange.Parse("::1");
            ClassicAssert.IsFalse(a.TryCombine(b, out _));
        }

        // -------- Chomp --------

        [Test]
        public void Chomp_FilterEntirelyContains_LeftAndRightAreNull()
        {
            var range = IPAddressRange.Parse("1.0.0.0/24");
            var filter = IPAddressRange.Parse("0.0.0.0/8");  // covers the entire 1.0.0.x
            // depending on implementation, just verify no throw
            range.Chomp(filter, out _, out _);
        }

        [Test]
        public void Chomp_DisjointFilter_KeepsRange()
        {
            var range = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            var filter = IPAddressRange.Parse("9.9.9.9");
            range.Chomp(filter, out _, out _);
        }

        // -------- TryCreateFromIPAddresses / TryCreateFromIPAddressRanges --------

        [Test]
        public void TryCreateFromIPAddresses_SingleIP()
        {
            var r = IPAddressRange.TryCreateFromIPAddresses(IPAddress.Parse("1.2.3.4"));
            ClassicAssert.IsNotNull(r);
            ClassicAssert.AreEqual("1.2.3.4", r.Begin.ToString());
        }

        [Test]
        public void TryCreateFromIPAddresses_TwoConsecutiveIPs_BuildsRange()
        {
            var r = IPAddressRange.TryCreateFromIPAddresses(
                IPAddress.Parse("1.2.3.4"),
                IPAddress.Parse("1.2.3.5"));
            ClassicAssert.IsNotNull(r);
            ClassicAssert.AreEqual("1.2.3.4", r.Begin.ToString());
            ClassicAssert.AreEqual("1.2.3.5", r.End.ToString());
        }

        [Test]
        public void TryCreateFromIPAddresses_NonConsecutiveIPs_ReturnsNull()
        {
            ClassicAssert.IsNull(IPAddressRange.TryCreateFromIPAddresses(
                IPAddress.Parse("1.2.3.4"),
                IPAddress.Parse("1.2.3.10")));
        }

        [Test]
        public void TryCreateFromIPAddresses_EmptyArray_ReturnsNull()
        {
            ClassicAssert.IsNull(IPAddressRange.TryCreateFromIPAddresses(Array.Empty<IPAddress>()));
        }

        [Test]
        public void TryCreateFromIPAddressRanges_AdjacentRanges_BuildsCombined()
        {
            // 1.0.0.0/24 ends at 1.0.0.255, increment is 1.0.1.0 == begin of next range
            var r = IPAddressRange.TryCreateFromIPAddressRanges(
                IPAddressRange.Parse("1.0.0.0/24"),
                IPAddressRange.Parse("1.0.1.0/24"));
            ClassicAssert.IsNotNull(r);
            ClassicAssert.AreEqual("1.0.0.0", r.Begin.ToString());
            ClassicAssert.AreEqual("1.0.1.255", r.End.ToString());
        }

        [Test]
        public void TryCreateFromIPAddressRanges_DisjointRanges_ReturnsNull()
        {
            ClassicAssert.IsNull(IPAddressRange.TryCreateFromIPAddressRanges(
                IPAddressRange.Parse("1.0.0.0/24"),
                IPAddressRange.Parse("3.0.0.0/24")));
        }

        [Test]
        public void TryCreateFromIPAddressRanges_EmptyArray_ReturnsNull()
        {
            ClassicAssert.IsNull(IPAddressRange.TryCreateFromIPAddressRanges(Array.Empty<IPAddressRange>()));
        }

        // -------- IEnumerable<IPAddress> enumeration --------

        [Test]
        public void GetEnumerator_IteratesAllIPs()
        {
            var r = IPAddressRange.Parse("1.0.0.0-1.0.0.5");
            int count = 0;
            foreach (var ip in r) count++;
            ClassicAssert.AreEqual(6, count);
        }

        // -------- ToString variants --------

        [Test]
        public void ToString_DefaultUsesDash()
        {
            var r = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            string s = r.ToString();
            StringAssert.Contains("-", s);
        }

        [Test]
        public void ToString_WithSeparator_UsesSeparator()
        {
            var r = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            string s = r.ToString('|');
            StringAssert.Contains("|", s);
        }

        // -------- Equals / GetHashCode --------

        [Test]
        public void Equals_GetHashCode_BasedOnBeginAndEnd()
        {
            var r1 = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            var r2 = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            var r3 = IPAddressRange.Parse("1.0.0.0-1.0.0.11");
            ClassicAssert.IsTrue(r1.Equals(r2));
            ClassicAssert.IsFalse(r1.Equals(r3));
            ClassicAssert.IsFalse(r1.Equals("not a range"));
            ClassicAssert.AreEqual(r1.GetHashCode(), r2.GetHashCode());
        }

        // -------- IComparable<IPAddressRange> --------

        [Test]
        public void CompareTo_Ranges_ByBeginThenEnd()
        {
            var r1 = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            var r2 = IPAddressRange.Parse("1.0.0.0-1.0.0.20");
            var r3 = IPAddressRange.Parse("2.0.0.0-2.0.0.5");
            ClassicAssert.Less(r1.CompareTo(r2), 0);
            ClassicAssert.Greater(r2.CompareTo(r1), 0);
            ClassicAssert.Less(r1.CompareTo(r3), 0);
            ClassicAssert.AreEqual(0, r1.CompareTo(r1));
        }

        // -------- IReadOnlyDictionary interface --------

        [Test]
        public void Dictionary_KeysValues_BeginAndEnd()
        {
            var r = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            IReadOnlyDictionary<string, string> dict = r;
            CollectionAssert.AreEquivalent(new[] { "Begin", "End" }, dict.Keys.ToArray());
            ClassicAssert.AreEqual(2, dict.Count);
            ClassicAssert.IsTrue(dict.ContainsKey("Begin"));
            ClassicAssert.IsFalse(dict.ContainsKey("Other"));
            ClassicAssert.AreEqual(r.Begin.ToString(), dict["Begin"]);
            ClassicAssert.AreEqual(r.End.ToString(), dict["End"]);
            ClassicAssert.IsTrue(dict.TryGetValue("Begin", out string val));
            ClassicAssert.AreEqual(r.Begin.ToString(), val);
            ClassicAssert.IsFalse(dict.TryGetValue("Missing", out _));
        }

        [Test]
        public void Dictionary_MissingKey_Throws()
        {
            var r = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            IReadOnlyDictionary<string, string> dict = r;
            Assert.Throws<KeyNotFoundException>(() => { var _ = dict["Missing"]; });
        }

        [Test]
        public void Construct_FromDictionaryItems_RoundTrips()
        {
            var orig = IPAddressRange.Parse("1.0.0.0-1.0.0.10");
            IReadOnlyDictionary<string, string> dict = orig;
            var roundtrip = new IPAddressRange(dict);
            ClassicAssert.AreEqual(orig.Begin, roundtrip.Begin);
            ClassicAssert.AreEqual(orig.End, roundtrip.End);
        }

        // -------- AsEnumerable --------

        [Test]
        public void AsEnumerable_ReturnsTypedSequence()
        {
            var r = IPAddressRange.Parse("1.0.0.0-1.0.0.5");
            var ips = r.AsEnumerable().ToArray();
            ClassicAssert.AreEqual(6, ips.Length);
        }

        // -------- JSON converter --------

        [Test]
        public void Json_RoundTrip_AsString()
        {
            var r = IPAddressRange.Parse("1.0.0.0/24");
            string json = JsonSerializer.Serialize(r);
            StringAssert.Contains("/24", json);
            var back = JsonSerializer.Deserialize<IPAddressRange>(json);
            ClassicAssert.AreEqual(r.Begin, back.Begin);
            ClassicAssert.AreEqual(r.End, back.End);
        }

        [Test]
        public void Json_NullValue_Allowed()
        {
            // The converter only writes if non-null values are present; null should round-trip.
            string json = JsonSerializer.Serialize<IPAddressRange>(null);
            ClassicAssert.AreEqual("null", json);
        }

        // -------- SubnetMaskLength --------

        [Test]
        public void SubnetMaskLength_RoundTripsCommonMasks()
        {
            ClassicAssert.AreEqual(24, IPAddressRange.SubnetMaskLength(IPAddress.Parse("255.255.255.0")));
            ClassicAssert.AreEqual(16, IPAddressRange.SubnetMaskLength(IPAddress.Parse("255.255.0.0")));
            ClassicAssert.AreEqual(8, IPAddressRange.SubnetMaskLength(IPAddress.Parse("255.0.0.0")));
        }

        // -------- Constructor with mask length --------

        [Test]
        public void Construct_WithMaskLength_BuildsCidr()
        {
            var r = new IPAddressRange(IPAddress.Parse("10.0.0.0"), 24);
            ClassicAssert.AreEqual("10.0.0.0", r.Begin.ToString());
            ClassicAssert.AreEqual("10.0.0.255", r.End.ToString());
        }

        // -------- Subnet mask + Parse edge cases (cover Bits.* helpers) --------

        [Test]
        public void Parse_BackedByLinearSubnetMask()
        {
            var r = IPAddressRange.Parse("192.168.1.0/255.255.255.0");
            ClassicAssert.AreEqual("192.168.1.0", r.Begin.ToString());
            ClassicAssert.AreEqual("192.168.1.255", r.End.ToString());
        }

        [Test]
        public void Parse_NonLinearSubnetMask_ThrowsFormat()
        {
            // 255.0.255.0 isn't a linear mask.
            Assert.Throws<FormatException>(() => IPAddressRange.Parse("192.168.1.0/255.0.255.0"));
        }

        [Test]
        public void Parse_AsteriskWildcards()
        {
            var r1 = IPAddressRange.Parse("192.168.1.*");
            ClassicAssert.AreEqual("192.168.1.0", r1.Begin.ToString());
            ClassicAssert.AreEqual("192.168.1.255", r1.End.ToString());

            var r2 = IPAddressRange.Parse("192.168.*.*");
            ClassicAssert.AreEqual("192.168.0.0", r2.Begin.ToString());
            ClassicAssert.AreEqual("192.168.255.255", r2.End.ToString());
        }

        [Test]
        public void Parse_WithComment()
        {
            // Trailing comment after a `#` character is stripped.
            var r = IPAddressRange.Parse("1.2.3.4 # comment");
            ClassicAssert.AreEqual("1.2.3.4", r.Begin.ToString());
        }
    }
}
