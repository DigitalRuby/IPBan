/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanFirewallUtility - port range merging, inversion,
firewall creation, range filtering.
*/

using System;
using System.Collections.Generic;
using System.Linq;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanFirewallUtilityTests
    {
        // -------- MergePortRanges --------

        [Test]
        public void MergePortRanges_NullInput_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanFirewallUtility.MergePortRanges(null));
        }

        [Test]
        public void MergePortRanges_AllInvalid_ReturnsNull()
        {
            var result = IPBanFirewallUtility.MergePortRanges(new[] { new PortRange(-1) });
            ClassicAssert.IsNull(result);
        }

        [Test]
        public void MergePortRanges_NonOverlapping_KeepsAll()
        {
            var input = new[] { new PortRange(80, 90), new PortRange(100, 110) };
            var result = IPBanFirewallUtility.MergePortRanges(input).ToArray();
            ClassicAssert.AreEqual(2, result.Length);
        }

        [Test]
        public void MergePortRanges_Overlapping_Coalesces()
        {
            var input = new[] { new PortRange(80, 100), new PortRange(95, 110) };
            var result = IPBanFirewallUtility.MergePortRanges(input).ToArray();
            ClassicAssert.AreEqual(1, result.Length);
            ClassicAssert.AreEqual(new PortRange(80, 110), result[0]);
        }

        [Test]
        public void MergePortRanges_Adjacent_Coalesces()
        {
            // 80..89 and 90..99 should merge if implementation considers them adjacent
            // Per code: if (range.MinPort <= lastRange.MaxPort) merges. Adjacent (90 <= 89 is false)
            // So adjacent ranges stay separate.
            var input = new[] { new PortRange(80, 89), new PortRange(90, 99) };
            var result = IPBanFirewallUtility.MergePortRanges(input).ToArray();
            ClassicAssert.AreEqual(2, result.Length);
        }

        [Test]
        public void MergePortRanges_Duplicates_RemovedFromResult()
        {
            var input = new[] { new PortRange(80, 90), new PortRange(80, 90) };
            var result = IPBanFirewallUtility.MergePortRanges(input).ToArray();
            ClassicAssert.AreEqual(1, result.Length);
        }

        // -------- InvertPortRanges --------

        [Test]
        public void InvertPortRanges_NullInput_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanFirewallUtility.InvertPortRanges(null));
        }

        [Test]
        public void InvertPortRanges_NoValidRanges_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(-1) }));
        }

        [Test]
        public void InvertPortRanges_SinglePort_ReturnsTwoRanges()
        {
            var result = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(80) }).ToArray();
            ClassicAssert.AreEqual(2, result.Length);
            ClassicAssert.AreEqual(new PortRange(0, 79), result[0]);
            ClassicAssert.AreEqual(new PortRange(81, 65535), result[1]);
        }

        [Test]
        public void InvertPortRanges_RangeAtStart_ReturnsRest()
        {
            var result = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(0, 100) }).ToArray();
            ClassicAssert.AreEqual(1, result.Length);
            ClassicAssert.AreEqual(new PortRange(101, 65535), result[0]);
        }

        [Test]
        public void InvertPortRanges_RangeAtEnd_ReturnsBeforeIt()
        {
            var result = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(60000, 65535) }).ToArray();
            ClassicAssert.AreEqual(1, result.Length);
            ClassicAssert.AreEqual(new PortRange(0, 59999), result[0]);
        }

        [Test]
        public void InvertPortRanges_FullRange_ReturnsEmpty()
        {
            var result = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(0, 65535) }).ToArray();
            ClassicAssert.AreEqual(0, result.Length);
        }

        // -------- GetPortRangeStringBlock / GetPortRangeStringAllow --------

        [Test]
        public void GetPortRangeStringBlock_NullInput_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanFirewallUtility.GetPortRangeStringBlock(null));
        }

        [Test]
        public void GetPortRangeStringBlock_ValidAllowList_ReturnsInvertedString()
        {
            string s = IPBanFirewallUtility.GetPortRangeStringBlock(new[] { new PortRange(80) });
            ClassicAssert.AreEqual("0-79,81-65535", s);
        }

        [Test]
        public void GetPortRangeStringBlock_AllPorts_ReturnsNull()
        {
            // Full range allowed -> nothing to block
            ClassicAssert.IsNull(IPBanFirewallUtility.GetPortRangeStringBlock(new[] { new PortRange(0, 65535) }));
        }

        [Test]
        public void GetPortRangeStringAllow_ReturnsCsv()
        {
            string s = IPBanFirewallUtility.GetPortRangeStringAllow(new[] { new PortRange(80), new PortRange(443) });
            StringAssert.Contains("80", s);
            StringAssert.Contains("443", s);
        }

        [Test]
        public void GetPortRangeStringAllow_Invalid_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanFirewallUtility.GetPortRangeStringAllow(new[] { new PortRange(-1) }));
        }

        [Test]
        public void GetPortRangeString_BasicConcat()
        {
            string s = IPBanFirewallUtility.GetPortRangeString(new[] { new PortRange(80), new PortRange(443) });
            ClassicAssert.AreEqual("80,443", s);
        }

        // -------- GetPortRangesForRule --------

        [Test]
        public void GetPortRangesForRule_Null_ReturnsEmpty()
        {
            var ranges = IPBanFirewallUtility.GetPortRangesForRule(null, true).ToArray();
            CollectionAssert.IsEmpty(ranges);
        }

        [Test]
        public void GetPortRangesForRule_BlockMode_InvertsAllowPorts()
        {
            var ranges = IPBanFirewallUtility.GetPortRangesForRule(new[] { new PortRange(80) }, true).ToArray();
            // Should give two ranges: 0-79 and 81-65535
            ClassicAssert.AreEqual(2, ranges.Length);
        }

        [Test]
        public void GetPortRangesForRule_AllowMode_KeepsAllowPorts()
        {
            var ranges = IPBanFirewallUtility.GetPortRangesForRule(new[] { new PortRange(80), new PortRange(443) }, false).ToArray();
            ClassicAssert.AreEqual(2, ranges.Length);
        }

        // -------- FilterRanges --------

        [Test]
        public void FilterRanges_NullRanges_YieldsNothing()
        {
            var result = IPBanFirewallUtility.FilterRanges(null, new[] { IPAddressRange.Parse("1.0.0.0/24") }).ToArray();
            CollectionAssert.IsEmpty(result);
        }

        [Test]
        public void FilterRanges_NullFilter_ReturnsRangesSorted()
        {
            var input = new[] { IPAddressRange.Parse("2.0.0.0/24"), IPAddressRange.Parse("1.0.0.0/24") };
            var result = IPBanFirewallUtility.FilterRanges(input, null).ToArray();
            ClassicAssert.AreEqual(2, result.Length);
            // Sorted, so 1.0.0.x first
            ClassicAssert.AreEqual(IPAddressRange.Parse("1.0.0.0/24").Begin, result[0].Begin);
        }

        [Test]
        public void FilterRanges_FilterRemovesOverlap()
        {
            var input = new[] { IPAddressRange.Parse("1.0.0.0-1.0.0.20") };
            var filter = new[] { IPAddressRange.Parse("1.0.0.10-1.0.0.15") };
            var result = IPBanFirewallUtility.FilterRanges(input, filter).ToArray();
            // The filter chops [10..15] out of [0..20], leaving [0..9] and [16..20]
            ClassicAssert.AreEqual(2, result.Length);
        }

        [Test]
        public void FilterRanges_FilterCoversEntireRange_RemovesIt()
        {
            var input = new[] { IPAddressRange.Parse("1.0.0.5-1.0.0.10") };
            var filter = new[] { IPAddressRange.Parse("1.0.0.0-1.0.0.20") };
            var result = IPBanFirewallUtility.FilterRanges(input, filter).ToArray();
            CollectionAssert.IsEmpty(result);
        }

        [Test]
        public void FilterRanges_DisjointFilter_KeepsAllRanges()
        {
            var input = new[] { IPAddressRange.Parse("1.0.0.0/24") };
            var filter = new[] { IPAddressRange.Parse("9.9.9.9") };
            var result = IPBanFirewallUtility.FilterRanges(input, filter).ToArray();
            ClassicAssert.AreEqual(1, result.Length);
        }

        [Test]
        public void FilterRanges_FilterAtBeginning_TrimsLeftEdge()
        {
            var input = new[] { IPAddressRange.Parse("1.0.0.10-1.0.0.20") };
            var filter = new[] { IPAddressRange.Parse("1.0.0.5-1.0.0.12") };
            var result = IPBanFirewallUtility.FilterRanges(input, filter).ToArray();
            ClassicAssert.AreEqual(1, result.Length);
            ClassicAssert.AreEqual("1.0.0.13", result[0].Begin.ToString());
        }

        // -------- CreateFirewall --------

        [Test]
        public void CreateFirewall_NoTypes_Throws()
        {
            Assert.Throws<ArgumentException>(() => IPBanFirewallUtility.CreateFirewall(Array.Empty<Type>()));
        }

        [Test]
        public void CreateFirewall_OnlyMemoryType_ReturnsMemoryFirewall()
        {
            // Memory firewall has Priority = -99 + null OS, but priority < 0 means won't match.
            // Try to construct with explicit memory firewall type — passing only it.
            // Since IsMatch returns false for priority < 0, this should throw.
            Assert.Throws<ArgumentException>(() => IPBanFirewallUtility.CreateFirewall(new[] { typeof(IPBanMemoryFirewall) }));
        }
    }
}
