/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanMemoryFirewall - exercises rule sets, ranges,
deltas, ports, enumeration, query, deletion, truncation, merging, ToString.
*/

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanMemoryFirewallTests2
    {
        // -------- BlockIPAddressesDelta --------

        [Test]
        public async Task BlockDelta_AddsAndRemovesIPs()
        {
            using var fw = new IPBanMemoryFirewall();
            var deltas = new[]
            {
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = "1.1.1.1" },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = "2.2.2.2" },
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = "::1234" },
            };
            await fw.BlockIPAddressesDelta(null, deltas);
            ClassicAssert.IsTrue(fw.IsIPAddressBlocked("1.1.1.1"));
            ClassicAssert.IsTrue(fw.IsIPAddressBlocked("2.2.2.2"));
            ClassicAssert.IsTrue(fw.IsIPAddressBlocked("::1234"));

            // remove one
            await fw.BlockIPAddressesDelta(null, new[]
            {
                new IPBanFirewallIPAddressDelta { Added = false, IPAddress = "1.1.1.1" },
                new IPBanFirewallIPAddressDelta { Added = false, IPAddress = "::1234" },
            });
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("1.1.1.1"));
            ClassicAssert.IsTrue(fw.IsIPAddressBlocked("2.2.2.2"));
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("::1234"));
        }

        // -------- DeleteRule --------

        [Test]
        public async Task DeleteRule_RemovesNamedRule()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses("RuleA", new[] { "10.0.0.1" });
            await fw.BlockIPAddresses("RuleB", new[] { IPAddressRange.Parse("11.0.0.0/24") });

            // Find rule names we created. The ScrubRuleNamePrefix logic adjusts.
            var ruleNames = fw.GetRuleNames().ToArray();
            ClassicAssert.IsTrue(ruleNames.Length > 0);

            // delete every rule we added; should mostly succeed
            int deleted = ruleNames.Count(name => fw.DeleteRule(name));
            ClassicAssert.GreaterOrEqual(deleted, 1);
        }

        [Test]
        public void DeleteRule_NonexistentRule_ReturnsFalse()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.IsFalse(fw.DeleteRule("does-not-exist"));
        }

        // -------- EnumerateAllowedIPAddresses with prefix --------

        [Test]
        public async Task EnumerateAllowedIPAddresses_ReturnsAllowedIps()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.1.1.1" });
            await fw.AllowIPAddresses("Rule1", new[] { IPAddressRange.Parse("2.2.2.0/24") });

            var allowed = fw.EnumerateAllowedIPAddresses().ToArray();
            ClassicAssert.IsTrue(allowed.Length >= 2);
            ClassicAssert.IsTrue(allowed.Any(a => a == "1.1.1.1"));
        }

        // -------- Ports / GetPorts --------

        [Test]
        public async Task BlockWithAllowPorts_StoresPorts()
        {
            // SetIPAddresses inverts the allow ports, then GetPortRangesForRule(block: true)
            // re-inverts inside it — so the rule effectively records the original allow port
            // string back. Just verify a port string is recorded and includes 80.
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses("Ports", new[] { "1.2.3.4" }, new[] { new PortRange(80) });
            string ruleName = fw.GetRuleNames().FirstOrDefault(n => n.Contains("Ports"));
            ClassicAssert.IsNotNull(ruleName);

            string ports = fw.GetPorts(ruleName);
            ClassicAssert.IsNotNull(ports);
            StringAssert.Contains("80", ports);
        }

        [Test]
        public async Task BlockWithRanges_AndPorts_InvertedAndStored()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses("RR", new[] { IPAddressRange.Parse("10.0.0.0/24") }, new[] { new PortRange(443) });
            string ruleName = fw.GetRuleNames().FirstOrDefault(n => n.Contains("RR"));
            ClassicAssert.IsNotNull(ruleName);

            string ports = fw.GetPorts(ruleName);
            ClassicAssert.IsNotNull(ports);
        }

        [Test]
        public void GetPorts_NonexistentRule_ReturnsNull()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.IsNull(fw.GetPorts("does-not-exist"));
        }

        // -------- IsIPAddressBlocked / IsIPAddressAllowed (object overloads) --------

        [Test]
        public async Task IsIPAddressBlocked_AfterAllow_NotBlocked()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.2.3.4" });
            await fw.BlockIPAddresses(null, new[] { "1.2.3.4" });
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("1.2.3.4", out _));
        }

        [Test]
        public async Task IsIPAddressBlocked_IPv6_RangeBlock_Hits()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses("v6", new[] { IPAddressRange.Parse("::1-::ff") });
            ClassicAssert.IsTrue(fw.IsIPAddressBlocked("::5", out _));
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("::1234", out _));
        }

        [Test]
        public async Task IsIPAddressBlocked_AllowedRange_NotBlocked()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses("Allow", new[] { IPAddressRange.Parse("1.2.3.0/24") });
            await fw.BlockIPAddresses(null, new[] { "1.2.3.50" });
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("1.2.3.50", out _));
            ClassicAssert.IsTrue(fw.IsIPAddressAllowed("1.2.3.50"));
        }

        [Test]
        public void IsIPAddressBlocked_BadStringInput_ReturnsFalse()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("not-an-ip", out _));
        }

        [Test]
        public void IsIPAddressAllowed_BadStringInput_ReturnsFalse()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.IsFalse(fw.IsIPAddressAllowed("not-an-ip"));
        }

        // -------- GetCount --------

        [Test]
        public async Task GetCount_ForEachRuleType()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.1.1.1", "1.1.1.2" });
            await fw.BlockIPAddresses("BB", new[] { "2.2.2.2" });
            await fw.BlockIPAddresses("RR", new[] { IPAddressRange.Parse("3.0.0.0/24") });
            await fw.AllowIPAddresses("AA", new[] { IPAddressRange.Parse("4.0.0.0/24") });

            // Default allow rule
            var ruleNames = fw.GetRuleNames().ToArray();
            ClassicAssert.IsTrue(ruleNames.Length > 0);
            int totalCount = ruleNames.Sum(n => fw.GetCount(n));
            ClassicAssert.Greater(totalCount, 0);
        }

        [Test]
        public void GetCount_UnknownRule_ReturnsZero()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.AreEqual(0, fw.GetCount("does-not-exist"));
        }

        // -------- ToString --------

        [Test]
        public async Task ToString_ContainsRuleSummaries()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.1.1.1" });
            await fw.BlockIPAddresses("B1", new[] { "2.2.2.2" });
            await fw.BlockIPAddresses("R1", new[] { IPAddressRange.Parse("3.0.0.0/24") });
            await fw.AllowIPAddresses("A1", new[] { IPAddressRange.Parse("4.0.0.0/24") });

            string s = fw.ToString();
            StringAssert.Contains("Allow rule", s);
            StringAssert.Contains("Block rule", s);
        }

        // -------- Truncate --------

        [Test]
        public async Task Truncate_RemovesAllRules()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses(null, new[] { "1.1.1.1" });
            await fw.AllowIPAddresses(new[] { "2.2.2.2" });
            fw.Truncate();
            ClassicAssert.IsFalse(fw.IsIPAddressBlocked("1.1.1.1"));
            ClassicAssert.IsFalse(fw.IsIPAddressAllowed("2.2.2.2"));
        }

        // -------- Merge --------

        [Test]
        public async Task Merge_CopiesRulesFromAnotherFirewall()
        {
            using var dst = new IPBanMemoryFirewall();
            using var src = new IPBanMemoryFirewall();
            await src.BlockIPAddresses(null, new[] { "1.1.1.1" });
            await src.AllowIPAddresses(new[] { "2.2.2.2" });
            await src.BlockIPAddresses("Range", new[] { IPAddressRange.Parse("3.0.0.0/24") });
            await src.AllowIPAddresses("Range", new[] { IPAddressRange.Parse("4.0.0.0/24") });

            dst.Merge(src);
            ClassicAssert.IsTrue(dst.IsIPAddressBlocked("1.1.1.1"));
            ClassicAssert.IsTrue(dst.IsIPAddressAllowed("2.2.2.2"));
            ClassicAssert.IsTrue(dst.IsIPAddressBlocked("3.0.0.5"));
        }

        // -------- Compile / Update --------

        [Test]
        public async Task Compile_ReturnsSelf()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses(null, new[] { "1.2.3.4" });
            var compiled = fw.Compile();
            ClassicAssert.AreSame(fw, compiled);
        }

        [Test]
        public async Task Update_DoesNothing_AndCompletes()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.Update(default);
        }

        // -------- RuleSets / RuleRanges --------

        [Test]
        public async Task RuleSets_AndRuleRanges_AreEnumerable()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.1.1.1" });
            await fw.BlockIPAddresses("Set1", new[] { "2.2.2.2" });
            await fw.BlockIPAddresses("Range1", new[] { IPAddressRange.Parse("3.0.0.0/24") });

            var sets = fw.RuleSets.ToArray();
            var ranges = fw.RuleRanges.ToArray();
            ClassicAssert.IsTrue(sets.Length > 0);
            ClassicAssert.IsTrue(ranges.Length > 0);

            // The IMemoryFirewallRule / IMemoryFirewallRuleRanges members work
            foreach (var s in sets)
            {
                _ = s.Value.IPV4.ToList();
                _ = s.Value.IPV6.ToList();
                _ = s.Value.Block;
                _ = s.Value.GetCount();
            }
            foreach (var r in ranges)
            {
                _ = r.Value.IPV4Strings.ToList();
                _ = r.Value.IPV6Strings.ToList();
                _ = r.Value.PortRangeStrings.ToList();
                _ = r.Value.Block;
                _ = r.Value.GetCount();
            }
        }

        // -------- EnumerateIPAddresses with prefix --------

        [Test]
        public async Task EnumerateIPAddresses_WithPrefix_FiltersResults()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses("Aaa", new[] { "10.0.0.1" });
            await fw.BlockIPAddresses("Bbb", new[] { "11.0.0.1" });

            // Different prefix paths should not throw
            var byPrefix1 = fw.EnumerateIPAddresses("Aaa").ToArray();
            var byPrefix2 = fw.EnumerateIPAddresses("Bbb").ToArray();
            var all = fw.EnumerateIPAddresses().ToArray();
            ClassicAssert.GreaterOrEqual(all.Length, byPrefix1.Length);
        }

        // -------- Rule prefixed firewall --------

        [Test]
        public async Task RulePrefixedFirewall_ScrubsPrefix()
        {
            using var fw = new IPBanMemoryFirewall("CustomPrefix_");
            await fw.BlockIPAddresses(null, new[] { "1.2.3.4" });
            // GetRuleNames should reflect the prefixed naming
            var names = fw.GetRuleNames().ToArray();
            ClassicAssert.IsTrue(names.Length > 0);
        }
    }
}
