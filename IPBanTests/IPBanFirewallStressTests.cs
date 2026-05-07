/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

High-volume stress tests for IPBanFirewall implementations. These exercise the
block / enumerate / truncate / compile / delta paths at 10k–20k IPs, which is
where COM-handle leaks, lock-coverage gaps, and quadratic-time bugs in the
Windows firewall implementation surface in real deployments.

Tests run against the real platform firewall (Windows Firewall on Windows,
firewalld / iptables on Linux). They share the same setup/teardown pattern as
IPBanFirewallTests and are tagged with [Category("StressTest")] so they can be
filtered out of fast CI runs.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    [Category("StressTest")]
    public class IPBanFirewallStressTests
    {
        // Use TEST-NET-2 (RFC 5737) to avoid colliding with anything operational on the host.
        private const byte StressOctet1 = 198;
        private const byte StressOctet2 = 51;

        // Type as IPBanBaseFirewall (not IIPBanFirewall) so we can call Compile() — the
        // interface doesn't expose it, but the base class does.
        private static readonly string[] StressIPs10000 = GenerateIPs(10_000);
        private static readonly string[] StressIPs11000 = GenerateIPs(11_000);
        private static readonly string[] StressIPs20000 = GenerateIPs(20_000);

        private IPBanBaseFirewall firewall;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            firewall = (IPBanBaseFirewall)IPBanFirewallUtility.CreateFirewall(IPBanFirewallTests.firewallTypes);
            ClassicAssert.AreNotEqual(typeof(IPBanMemoryFirewall), firewall.GetType());
        }

        [SetUp]
        public void SetUp()
        {
            firewall.Truncate();
        }

        [TearDown]
        public void TearDown()
        {
            firewall.Truncate();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            firewall.Dispose();
            firewall = null;
        }

        // ----- helpers -----

        /// <summary>Generate <paramref name="count"/> distinct IPs in TEST-NET-2.</summary>
        private static string[] GenerateIPs(int count)
        {
            string[] ips = new string[count];
            // Walk 198.51.X.Y deterministically. count up to 65 536 fits.
            for (int i = 0; i < count; i++)
            {
                byte octet3 = (byte)((i >> 8) & 0xFF);
                byte octet4 = (byte)(i & 0xFF);
                ips[i] = $"{StressOctet1}.{StressOctet2}.{octet3}.{octet4}";
            }
            return ips;
        }

        // ----- core scale tests -----

        /// <summary>
        /// Block 10 000 IPs and verify every one comes back through the three enumeration paths
        /// (EnumerateIPAddresses for ranges, EnumerateBannedIPAddresses for raw IPs, and
        /// IsIPAddressBlocked for spot checks). On Windows this exercises the rule-bucket
        /// allocation (1 000 per rule → 10 rules) and the COM enumeration / release paths.
        /// </summary>
        [Test]
        public void Block10000IPs_AllReachable()
        {
            string[] ips = StressIPs10000;
            var sw = Stopwatch.StartNew();

            ClassicAssert.IsTrue(firewall.BlockIPAddresses(null, ips).Sync(),
                "BlockIPAddresses returned false for the 10 000-IP batch");

            sw.Stop();
            TestContext.Out.WriteLine($"Block 10 000 IPs took {sw.ElapsedMilliseconds} ms");

            // EnumerateIPAddresses yields ranges; for /32 single-IPs, Begin == End == the IP.
            string[] enumerated = firewall.EnumerateIPAddresses()
                .Select(r => r.Begin.ToString())
                .ToArray();
            ClassicAssert.AreEqual(ips.Length, enumerated.Length,
                "EnumerateIPAddresses count must match the input");

            string[] banned = firewall.EnumerateBannedIPAddresses().ToArray();
            ClassicAssert.AreEqual(ips.Length, banned.Length,
                "EnumerateBannedIPAddresses count must match the input");

            // Spot-check IsIPAddressBlocked at the boundaries and middle.
            foreach (var sample in new[] { ips[0], ips[5_000], ips[^1] })
            {
                ClassicAssert.IsTrue(firewall.IsIPAddressBlocked(sample, out _),
                    $"IsIPAddressBlocked false for sampled ip {sample}");
            }
        }

        /// <summary>
        /// Block 20 000 IPs to push the rule count to ~20 (assuming 1 000 IPs per rule on
        /// Windows). The rule iteration path runs 20+ COM enumerations per cycle on Windows;
        /// without correct release, this is where handles previously leaked fastest.
        /// </summary>
        [Test]
        public void Block20000IPs_AllReachable()
        {
            string[] ips = StressIPs20000;
            var sw = Stopwatch.StartNew();

            ClassicAssert.IsTrue(firewall.BlockIPAddresses(null, ips).Sync(),
                "BlockIPAddresses returned false for the 20 000-IP batch");

            sw.Stop();
            TestContext.Out.WriteLine($"Block 20 000 IPs took {sw.ElapsedMilliseconds} ms");

            // The set of returned IPs must equal the set we sent — no duplicates, no losses.
            HashSet<string> returned = new(firewall.EnumerateBannedIPAddresses());
            HashSet<string> expected = new(ips);
            ClassicAssert.AreEqual(expected.Count, returned.Count,
                "Cardinality mismatch between input and EnumerateBannedIPAddresses");
            ClassicAssert.IsTrue(expected.SetEquals(returned),
                "Set of banned IPs does not match the input set");
        }

        /// <summary>
        /// Repeated block / truncate cycles at 10 k IPs. This is the workload that exposed the
        /// COM-handle leak in production — every cycle iterates and rewrites all rules. Pre-fix,
        /// each iteration leaked one COM RCW per rule; after enough cycles the firewall service
        /// would refuse new calls. Post-fix, this should run cleanly to completion.
        /// </summary>
        [Test]
        public void Block10000_TruncateCycles_NoExhaustion()
        {
            string[] ips = StressIPs10000;
            const int cycles = 5;
            for (int cycle = 1; cycle <= cycles; cycle++)
            {
                ClassicAssert.IsTrue(firewall.BlockIPAddresses(null, ips).Sync(),
                    $"Block failed in cycle {cycle}");
                ClassicAssert.AreEqual(ips.Length, firewall.EnumerateBannedIPAddresses().Count(),
                    $"Banned count wrong in cycle {cycle}");
                firewall.Truncate();
                ClassicAssert.AreEqual(0, firewall.EnumerateBannedIPAddresses().Count(),
                    $"Truncate did not clear all rules in cycle {cycle}");
            }
        }

        /// <summary>
        /// EnumerateBannedIPAddresses must work as a fully materialized list — calling
        /// .ToArray() must succeed, and the iteration must not leak resources or fail mid-way.
        /// On Windows the implementation reads each rule's RemoteAddresses under the lock and
        /// releases the COM RCW before yielding; this test ensures the rebuild against 10 k IPs
        /// stays correct.
        /// </summary>
        [Test]
        public void EnumerateBannedAtScale_Materializes()
        {
            string[] ips = StressIPs10000;
            firewall.BlockIPAddresses(null, ips).Sync();

            // Materialize twice — same result, no exception, no resource exhaustion the second time.
            string[] first = firewall.EnumerateBannedIPAddresses().ToArray();
            string[] second = firewall.EnumerateBannedIPAddresses().ToArray();

            ClassicAssert.AreEqual(ips.Length, first.Length);
            ClassicAssert.AreEqual(first.Length, second.Length);
            CollectionAssert.AreEquivalent(first, second);
        }

        /// <summary>
        /// Block 10 k IPs then call Compile(). Compile() iterates every rule from policy.Rules
        /// (Windows) or the equivalent on Linux — this is the path most likely to leak COM
        /// handles during steady-state firewall reconciliation. Verify the resulting memory
        /// firewall reports the same set of IPs as the input.
        /// </summary>
        [Test]
        public void Compile10000_ProducesMatchingMemoryFirewall()
        {
            string[] ips = StressIPs10000;
            firewall.BlockIPAddresses(null, ips).Sync();

            using var compiled = firewall.Compile();
            ClassicAssert.IsNotNull(compiled, "Compile returned null");

            HashSet<string> compiledSet = new(compiled.EnumerateBannedIPAddresses());
            HashSet<string> expected = new(ips);
            ClassicAssert.IsTrue(expected.SetEquals(compiledSet),
                $"Compiled memory firewall set differs (expected {expected.Count}, got {compiledSet.Count})");
        }

        /// <summary>
        /// Delta path at scale: start with 10 k, add 1 k new, remove 500 existing. Verify the
        /// resulting set matches the expected union/difference. This exercises the snapshot +
        /// release path inside BlockIPAddressesDelta that holds zero live COM RCWs across the
        /// delta computation.
        /// </summary>
        [Test]
        public void Delta10000_AddAndRemove_ProducesCorrectSet()
        {
            string[] initial = StressIPs10000;
            firewall.BlockIPAddresses(null, initial).Sync();

            // Build the delta: 1 000 net-new (offsets 10 000..10 999), and removal of the first 500.
            string[] toAdd = StressIPs11000.Skip(10_000).ToArray();
            string[] toRemove = initial.Take(500).ToArray();

            var delta = new List<IPBanFirewallIPAddressDelta>();
            foreach (var ip in toAdd)
            {
                delta.Add(new IPBanFirewallIPAddressDelta { Added = true, IPAddress = ip });
            }
            foreach (var ip in toRemove)
            {
                delta.Add(new IPBanFirewallIPAddressDelta { Added = false, IPAddress = ip });
            }

            ClassicAssert.IsTrue(firewall.BlockIPAddressesDelta(null, delta).Sync(),
                "BlockIPAddressesDelta returned false");

            HashSet<string> expected = new(initial);
            foreach (var ip in toAdd) expected.Add(ip);
            foreach (var ip in toRemove) expected.Remove(ip);

            HashSet<string> actual = new(firewall.EnumerateBannedIPAddresses());
            ClassicAssert.AreEqual(expected.Count, actual.Count,
                $"Cardinality mismatch after delta (expected {expected.Count}, got {actual.Count})");
            ClassicAssert.IsTrue(expected.SetEquals(actual),
                "Banned IPs after delta do not match the expected union/difference");
        }

        /// <summary>
        /// Truncate at scale must complete in bounded time and leave zero rules behind. This
        /// is also a smoke check that the rule-iteration during Truncate releases COM handles
        /// — a leaky implementation would slow down monotonically across repeated runs in the
        /// same process.
        /// </summary>
        [Test]
        public void Truncate10000_LeavesZeroRules()
        {
            string[] ips = StressIPs10000;
            firewall.BlockIPAddresses(null, ips).Sync();
            ClassicAssert.AreEqual(ips.Length, firewall.EnumerateBannedIPAddresses().Count());

            var sw = Stopwatch.StartNew();
            firewall.Truncate();
            sw.Stop();
            TestContext.Out.WriteLine($"Truncate of 10 000 IPs took {sw.ElapsedMilliseconds} ms");

            ClassicAssert.AreEqual(0, firewall.EnumerateBannedIPAddresses().Count(),
                "Truncate did not remove all banned IPs");
            ClassicAssert.AreEqual(0, firewall.EnumerateIPAddresses().Count(),
                "Truncate did not remove all IP ranges");
            CollectionAssert.IsEmpty(firewall.GetRuleNames(),
                "Truncate did not remove all rule names");
        }

        /// <summary>
        /// GetRuleNames at scale must return a stable, materialized list — the implementation
        /// must call ToList() before disposing the underlying RuleList, otherwise the lazy LINQ
        /// chain would read names from already-released COM RCWs.
        /// </summary>
        [Test]
        public void GetRuleNames_AtScale_IsMaterialized()
        {
            string[] ips = StressIPs10000;
            firewall.BlockIPAddresses(null, ips).Sync();

            // Two enumerations must produce the same sequence — not a transient/lazy view.
            string[] first = firewall.GetRuleNames().ToArray();
            string[] second = firewall.GetRuleNames().ToArray();

            ClassicAssert.IsTrue(first.Length > 0, "Expected at least one rule");
            CollectionAssert.AreEqual(first, second);
        }
    }
}
