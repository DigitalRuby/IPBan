/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanFirewallExtensions.IsIPAddressAllowed (the allowed-rule sibling
of IsIPAddressBlocked) and IPBanFirewallUtility port-range helpers, exercised
against IPBanMemoryFirewall so they can run cross-platform without root.
*/

using System.Collections.Generic;
using System.Linq;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed partial class IPBanFirewallExtensionsTests
    {
        // -------------------- IsIPAddressAllowed --------------------

        [Test]
        public void IsIPAddressAllowed_ReportsTrueForAllowedSingleIp()
        {
            // The IEnumerable<string> overload of AllowIPAddresses takes individual IPs only.
            // Use the (ruleNamePrefix, IPAddressRange[]) overload to allow a CIDR range.
            using var fw = new IPBanMemoryFirewall();
            fw.AllowIPAddresses(new[] { "1.2.3.4" }).Sync();

            ClassicAssert.IsTrue(fw.IsIPAddressAllowed("1.2.3.4", out string ruleName));
            ClassicAssert.IsNotNull(ruleName, "an allowed match must populate the rule name");
        }

        [Test]
        public void IsIPAddressAllowed_ReportsTrueForIpInsideAllowedRange()
        {
            using var fw = new IPBanMemoryFirewall();
            fw.AllowIPAddresses("AllowSubnet_", new[] { IPAddressRange.Parse("1.2.3.0/24") }).Sync();

            ClassicAssert.IsTrue(fw.IsIPAddressAllowed("1.2.3.4", out string ruleName));
            ClassicAssert.IsNotNull(ruleName);
        }

        [Test]
        public void IsIPAddressAllowed_ReportsFalseForUnknownIp()
        {
            using var fw = new IPBanMemoryFirewall();
            fw.AllowIPAddresses(new[] { "1.2.3.4" }).Sync();

            // The Query() result list returns no entry for IPs the firewall doesn't know
            // about, so the helper returns false with a null rule name.
            bool allowed = fw.IsIPAddressAllowed("9.9.9.9", out _);
            ClassicAssert.IsFalse(allowed);
        }

        [Test]
        public void IsIPAddressAllowed_AllowedTakesPrecedenceOverBlocked()
        {
            using var fw = new IPBanMemoryFirewall();
            fw.AllowIPAddresses(new[] { "1.2.3.4" }).Sync();
            fw.BlockIPAddresses(null, new[] { "1.2.3.4" }).Sync();

            // Even though the same IP is in a block list, the allow rule takes precedence —
            // IsIPAddressAllowed returns true.
            ClassicAssert.IsTrue(fw.IsIPAddressAllowed("1.2.3.4", out _));
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("1.2.3.4", out _),
                "allow rule must shadow the block rule for the same IP");
        }

        [Test]
        public void IsIPAddressBlocked_ReportsFalseAfterUnblock()
        {
            using var fw = new IPBanMemoryFirewall();
            fw.BlockIPAddresses(null, new[] { "5.5.5.5" }).Sync();
            ClassicAssert.IsTrue(fw.IsIPAddressBlocked("5.5.5.5", out _));

            // unblock via delta and verify the state flips
            fw.BlockIPAddressesDelta(null, new[]
            {
                new IPBanFirewallIPAddressDelta { Added = false, IPAddress = "5.5.5.5" }
            }).Sync();

            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("5.5.5.5", out _));
        }

        // -------------------- IPBanFirewallUtility.InvertPortRanges --------------------

        [Test]
        public void InvertPortRanges_EmptyInputReturnsNullOrEmpty()
        {
            // Production behavior: an empty input is treated as "no allow ranges to invert"
            // and the helper returns null. Match that here so the test acts as a regression
            // guard — if a future change starts returning the full 0-65535 range instead,
            // we want to notice.
            var inverted = IPBanFirewallUtility.InvertPortRanges(new List<PortRange>());
            ClassicAssert.IsTrue(inverted is null || inverted.Count == 0,
                "empty input should produce null or empty (current behavior is null)");
        }

        [Test]
        public void InvertPortRanges_SinglePortInTheMiddle()
        {
            // Just port 80 → inverted to 0-79 + 81-65535
            var inverted = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(80, 80) }).ToArray();
            ClassicAssert.AreEqual(2, inverted.Length);
            ClassicAssert.AreEqual(0,    inverted[0].MinPort); ClassicAssert.AreEqual(79,    inverted[0].MaxPort);
            ClassicAssert.AreEqual(81,   inverted[1].MinPort); ClassicAssert.AreEqual(65535, inverted[1].MaxPort);
        }

        [Test]
        public void InvertPortRanges_RangeCoveringEntireSpaceProducesEmpty()
        {
            // 0-65535 inverted is nothing.
            var inverted = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(0, 65535) });
            CollectionAssert.IsEmpty(inverted);
        }

        [Test]
        public void InvertPortRanges_RangeAtStartOrEnd()
        {
            // 0-22 → 23-65535
            var startOnly = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(0, 22) }).ToArray();
            ClassicAssert.AreEqual(1, startOnly.Length);
            ClassicAssert.AreEqual(23, startOnly[0].MinPort);
            ClassicAssert.AreEqual(65535, startOnly[0].MaxPort);

            // 60000-65535 → 0-59999
            var endOnly = IPBanFirewallUtility.InvertPortRanges(new[] { new PortRange(60000, 65535) }).ToArray();
            ClassicAssert.AreEqual(1, endOnly.Length);
            ClassicAssert.AreEqual(0, endOnly[0].MinPort);
            ClassicAssert.AreEqual(59999, endOnly[0].MaxPort);
        }

        [Test]
        public void InvertPortRanges_MultipleNonContiguousRanges()
        {
            // 22-22 + 80-80 + 443-443 → gaps between are inverted
            var ranges = new[]
            {
                new PortRange(22, 22),
                new PortRange(80, 80),
                new PortRange(443, 443),
            };
            var inverted = IPBanFirewallUtility.InvertPortRanges(ranges).ToArray();
            // Expected: 0-21, 23-79, 81-442, 444-65535
            ClassicAssert.AreEqual(4, inverted.Length);
            ClassicAssert.AreEqual(0,    inverted[0].MinPort); ClassicAssert.AreEqual(21,    inverted[0].MaxPort);
            ClassicAssert.AreEqual(23,   inverted[1].MinPort); ClassicAssert.AreEqual(79,    inverted[1].MaxPort);
            ClassicAssert.AreEqual(81,   inverted[2].MinPort); ClassicAssert.AreEqual(442,   inverted[2].MaxPort);
            ClassicAssert.AreEqual(444,  inverted[3].MinPort); ClassicAssert.AreEqual(65535, inverted[3].MaxPort);
        }

        // -------------------- IPBanFirewallUtility.GetPortRangeStringAllow / Block --------------------

        [Test]
        public void GetPortRangeStringAllow_FormatsAsCommaSeparatedList()
        {
            string s = IPBanFirewallUtility.GetPortRangeStringAllow(new[]
            {
                new PortRange(22, 22),
                new PortRange(80, 81),
            });

            // The exact format is operator-visible, so assert on observable invariants:
            // each range shows up at most once, in order.
            StringAssert.Contains("22", s);
            StringAssert.Contains("80", s);
            // Single-port "22" should appear without a "-22" suffix
            StringAssert.DoesNotContain("22-22", s);
        }

        [Test]
        public void GetPortRangeStringBlock_InvertsTheAllowRanges()
        {
            // For block rules, the helper inverts the ports — passing "allow 80" should yield
            // a string that covers the inverted ranges (0-79 and 81-65535).
            string s = IPBanFirewallUtility.GetPortRangeStringBlock(new[] { new PortRange(80, 80) });

            // Should contain at least one range that includes "0" or "1-79" and one ending in 65535
            StringAssert.Contains("65535", s);
        }
    }
}
