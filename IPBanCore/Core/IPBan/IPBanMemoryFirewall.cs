/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// In memory firewall that persists rules to disk. This is not meant to be used directly but rather to be used inside of other firewall implementations.
    /// Use the IsIPAddressBlocked method in your firewall implementation / packet injection / etc.
    /// Also great for unit testing.
    /// This class is thread safe.
    /// </summary>
    [RequiredOperatingSystemAttribute(null, Priority = -99)] // low priority, basically any other firewall is preferred unless this one is explicitly specified in the config
    [CustomName("Memory")]
    public class IPBanMemoryFirewall : IPBanBaseFirewall
    {
        public interface IMemoryFirewallRuleRanges
        {
            /// <summary>
            /// IPV4 ranges
            /// </summary>
            IEnumerable<string> IPV4 { get; }

            /// <summary>
            /// IPV6 ranges
            /// </summary>
            IEnumerable<string> IPV6 { get; }

            /// <summary>
            /// Port ranges, empty for none
            /// </summary>
            IEnumerable<string> PortRanges { get; }

            /// <summary>
            /// True to block, false to allow
            /// </summary>
            bool Block { get; }
        }

        public interface IMemoryFirewallRule
        {
            /// <summary>
            /// IPV4 set
            /// </summary>
            IEnumerable<string> IPV4 { get; }

            /// <summary>
            /// IPV6 set
            /// </summary>
            IEnumerable<string> IPV6 { get; }

            /// <summary>
            /// True to block, false to allow
            /// </summary>
            bool Block { get; }
        }

        private class MemoryFirewallRuleRanges : IComparer<IPV4Range>, IComparer<IPV6Range>, IMemoryFirewallRuleRanges
        {
            private static readonly List<PortRange> emptyPortRanges = new(0);

            private readonly List<IPV4Range> ipv4 = new();
            private readonly List<IPV6Range> ipv6 = new();
            private readonly List<PortRange> portRanges;

            public IEnumerable<string> IPV4 => ipv4.Select(r => r.ToIPAddressRange().ToString());
            public IEnumerable<string> IPV6 => ipv6.Select(r => r.ToIPAddressRange().ToString());
            public IEnumerable<string> PortRanges => portRanges.Select(r => r.ToString());

            public bool Block { get; }

            public string Name { get; }

            public MemoryFirewallRuleRanges(IEnumerable<IPAddressRange> ipRanges, List<PortRange> allowedPorts, bool block, string name)
            {
                List<IPAddressRange> ipRangesSorted = new(ipRanges);
                ipRangesSorted.Sort();
                allowedPorts ??= emptyPortRanges;
                Block = block;
                Name = name;
                foreach (IPAddressRange range in ipRangesSorted)
                {
                    // optimized storage, no pointers or other overhead
                    if (range.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        uint begin = range.Begin.ToUInt32();
                        uint end = range.End.ToUInt32();
                        Debug.Assert(end >= begin);
                        ipv4.Add(new IPV4Range { Begin = begin, End = end });
                    }
                    else
                    {
                        UInt128 begin = range.Begin.ToUInt128();
                        UInt128 end = range.End.ToUInt128();
                        Debug.Assert(end.CompareTo(begin) >= 0);
                        ipv6.Add(new IPV6Range { Begin = begin, End = end });
                    }
                }
                ipv4.TrimExcess();
                ipv6.TrimExcess();
                if (block)
                {
                    string portString = IPBanFirewallUtility.GetBlockPortRangeString(allowedPorts);
                    this.portRanges = (string.IsNullOrWhiteSpace(portString) ? new List<PortRange>(0) : portString.Split(',').Select(s => PortRange.Parse(s)).ToList());
                }
                else
                {
                    this.portRanges = allowedPorts;
                }
            }

            public bool Contains(System.Net.IPAddress ipAddressObj, int port)
            {
                if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return Contains(ipAddressObj.ToUInt32(), port);
                }
                return Contains(ipAddressObj.ToUInt128(), port);
            }

            public bool Contains(uint ipAddress, int port)
            {
                if (port > -1)
                {
                    foreach (PortRange range in portRanges)
                    {
                        if (port >= range.MinPort && port <= range.MaxPort)
                        {
                            return false;
                        }
                    }
                }
                return (ipv4.BinarySearch(new IPV4Range { Begin = ipAddress, End = ipAddress }, this) >= 0);
            }

            public bool Contains(UInt128 ipAddress, int port)
            {
                if (port > -1)
                {
                    foreach (PortRange range in portRanges)
                    {
                        if (port >= range.MinPort && port <= range.MaxPort)
                        {
                            return false;
                        }
                    }
                }
                return (ipv6.BinarySearch(new IPV6Range { Begin = ipAddress, End = ipAddress }, this) >= 0);
            }

            public IEnumerable<IPAddressRange> EnumerateIPAddressesRanges()
            {
                foreach (IPV4Range range in ipv4)
                {
                    yield return range.ToIPAddressRange();
                }
                foreach (IPV6Range range in ipv6)
                {
                    yield return range.ToIPAddressRange();
                }
            }

            int IComparer<IPV4Range>.Compare(IPV4Range x, IPV4Range y)
            {
                return x.CompareTo(y);
            }

            int IComparer<IPV6Range>.Compare(IPV6Range x, IPV6Range y)
            {
                return x.CompareTo(y);
            }
        }

        private class MemoryFirewallRule : IMemoryFirewallRule
        {
            private readonly HashSet<uint> ipv4 = new();
            private readonly HashSet<UInt128> ipv6 = new();
            private readonly List<PortRange> allowPorts = new();

            public IEnumerable<string> IPV4 => ipv4.Select(i => i.ToIPAddress().ToString());
            public IEnumerable<string> IPV6 => ipv6.Select(i => i.ToIPAddress().ToString());

            public bool Block { get; }

            public string Name { get; }

            public MemoryFirewallRule(bool block, string name)
            {
                Block = block;
                Name = name;
            }

            public void SetIPAddresses(IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowPorts)
            {
                ipv4.Clear();
                ipv6.Clear();
                this.allowPorts.Clear();
                foreach (string ipAddress in ipAddresses)
                {
                    if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                    {
                        if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            ipv4.Add(ipAddressObj.ToUInt32());
                        }
                        else
                        {
                            ipv6.Add(ipAddressObj.ToUInt128());
                        }
                    }
                }
                if (allowPorts is not null)
                {
                    this.allowPorts.AddRange(allowPorts);
                }
            }

            public void AddIPAddressesDelta(IEnumerable<IPBanFirewallIPAddressDelta> deltas, IEnumerable<PortRange> allowPorts = null)
            {
                foreach (IPBanFirewallIPAddressDelta delta in deltas)
                {
                    if (IPAddress.TryParse(delta.IPAddress, out IPAddress ipAddressObj))
                    {
                        if (delta.Added)
                        {
                            if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                ipv4.Add(ipAddressObj.ToUInt32());
                            }
                            else
                            {
                                ipv6.Add(ipAddressObj.ToUInt128());
                            }
                        }
                        else if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            ipv4.Remove(ipAddressObj.ToUInt32());
                        }
                        else
                        {
                            ipv6.Remove(ipAddressObj.ToUInt128());
                        }
                    }
                }
                this.allowPorts.Clear();
                if (allowPorts is not null)
                {
                    this.allowPorts.AddRange(allowPorts);
                }
            }

            public IEnumerable<string> EnumerateIPAddresses()
            {
                foreach (uint ipv4UInt in ipv4)
                {
                    yield return ipv4UInt.ToIPAddress().ToString();
                }
                foreach (UInt128 ipv6UInt128 in ipv6)
                {
                    yield return ipv6UInt128.ToIPAddress().ToString();
                }
            }

            public IEnumerable<IPAddressRange> EnumerateIPAddressesRanges()
            {
                foreach (uint ipv4UInt in ipv4)
                {
                    yield return new IPAddressRange(ipv4UInt.ToIPAddress());
                }
                foreach (UInt128 ipv6UInt128 in ipv6)
                {
                    yield return new IPAddressRange(ipv6UInt128.ToIPAddress());
                }
            }

            public bool Remove(uint ipv4UInt)
            {
                return ipv4.Remove(ipv4UInt);
            }

            public bool Remove(UInt128 ipv6UInt128)
            {
                return ipv6.Remove(ipv6UInt128);
            }

            public bool Contains(System.Net.IPAddress ipAddressObj, int port)
            {
                if (IsPortAllowed(port))
                {
                    return false;
                }
                else if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ipv4.Contains(ipAddressObj.ToUInt32());
                }
                return ipv6.Contains(ipAddressObj.ToUInt128());
            }

            public bool Contains(string ipAddress, int port)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                {
                    return Contains(ipAddressObj, port);
                }
                return false;
            }

            public bool Contains(uint ipv4UInt, int port)
            {
                return !IsPortAllowed(port) && ipv4.Contains(ipv4UInt);
            }

            public bool Contains(UInt128 ipv6UInt128, int port)
            {
                return !IsPortAllowed(port) && ipv6.Contains(ipv6UInt128);
            }

            public bool IsPortAllowed(int port)
            {
                return (port >= 0 && allowPorts.Any(p => p.Contains(port)));
            }
        }

        private readonly Dictionary<string, MemoryFirewallRuleRanges> blockRulesRanges = new();
        private readonly Dictionary<string, MemoryFirewallRule> blockRules = new();
        private readonly MemoryFirewallRule allowRule;
        private readonly Dictionary<string, MemoryFirewallRuleRanges> allowRuleRanges = new();

        /// <summary>
        /// Get all the rules with ranges
        /// </summary>
        public IEnumerable<KeyValuePair<string, IMemoryFirewallRuleRanges>> RuleRanges
        {
            get
            {
                lock (this)
                {
                    return blockRulesRanges
                        .Select(kv => new KeyValuePair<string, IMemoryFirewallRuleRanges>(kv.Key, kv.Value))
                        .Union(allowRuleRanges.Select(kv => new KeyValuePair<string, IMemoryFirewallRuleRanges>(kv.Key, kv.Value)))
                        .ToArray();
                }
            }
        }

        /// <summary>
        /// Get all the rules with sets
        /// </summary>
        public IEnumerable<KeyValuePair<string, IMemoryFirewallRule>> RuleSets
        {
            get
            {
                lock (this)
                {
                    IEnumerable<KeyValuePair<string, IMemoryFirewallRule>> allowRules = new KeyValuePair<string, IMemoryFirewallRule>[]
                    {
                        new KeyValuePair<string, IMemoryFirewallRule>(allowRule.Name, allowRule)
                    };
                    return blockRules
                        .Select(kv => new KeyValuePair<string, IMemoryFirewallRule>(kv.Key, kv.Value))
                        .Union(allowRules)
                        .ToArray();
                }
            }
        }

        private string ScrubRuleNamePrefix(string prefix, string ruleNamePrefix)
        {
            // in memory firewall does not have a count limit per rule, so remove the trailing underscore if any
            return (prefix + (ruleNamePrefix ?? string.Empty) + RuleSuffix).Trim('_');
        }

        protected override void OnDispose()
        {
            base.OnDispose();
            Truncate();
        }

        public IPBanMemoryFirewall(string rulePrefix = null) : base(rulePrefix)
        {
            allowRule = new MemoryFirewallRule(false, AllowRuleName);
        }

        public override Task Update(CancellationToken cancelToken)
        {
            return Task.CompletedTask;
        }

        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                allowRule.SetIPAddresses(ipAddresses, null);
            }
            return Task.FromResult<bool>(true);
        }

        public override Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            var allowedPortList = allowedPorts?.ToList();
            string ruleName = ScrubRuleNamePrefix(AllowRulePrefix, ruleNamePrefix);
            lock (this)
            {
                allowRuleRanges[ruleName] = new MemoryFirewallRuleRanges(ipAddresses, allowedPortList, false, ruleName);
            }
            return Task.FromResult<bool>(true);
        }

        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            string ruleName = ScrubRuleNamePrefix(BlockRulePrefix, ruleNamePrefix);
            lock (this)
            {
                if (!blockRules.TryGetValue(ruleName, out MemoryFirewallRule rule))
                {
                    blockRules[ruleName] = rule = new MemoryFirewallRule(true, ruleName);
                }
                rule.SetIPAddresses(ipAddresses, allowedPorts);
            }
            return Task.FromResult<bool>(true);
        }

        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            string ruleName = ScrubRuleNamePrefix(BlockRulePrefix, ruleNamePrefix);
            lock (this)
            {
                if (!blockRules.TryGetValue(ruleName, out MemoryFirewallRule rule))
                {
                    blockRules[ruleName] = rule = new MemoryFirewallRule(true, ruleName);
                }
                rule.AddIPAddressesDelta(ipAddresses, allowedPorts);
            }
            return Task.FromResult(true);
        }

        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            var portList = allowedPorts?.ToList();
            string ruleName = ScrubRuleNamePrefix(BlockRulePrefix, ruleNamePrefix);
            lock (this)
            {
                blockRulesRanges[ruleName] = new MemoryFirewallRuleRanges(ranges, portList, true, ruleName);
            }
            return Task.FromResult<bool>(true);
        }

        public override bool DeleteRule(string ruleName)
        {
            lock (this)
            {
                return blockRules.Remove(ruleName) || blockRulesRanges.Remove(ruleName);
            }
        }

        public override IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            lock (this)
            {
                List<string> ips = new();
                ips.AddRange(allowRule.EnumerateIPAddresses());
                foreach (var rule in allowRuleRanges)
                {
                    foreach (IPAddressRange range in rule.Value.EnumerateIPAddressesRanges())
                    {
                        if (range.Single)
                        {
                            ips.Add(range.Begin.ToString());
                        }
                        else
                        {
                            ips.Add(range.ToString());
                        }
                    }
                }
                return ips;
            }
        }

        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            List<string> ips = new();
            lock (this)
            {
                foreach (MemoryFirewallRule rule in blockRules.Values)
                {
                    foreach (string ipAddress in rule.EnumerateIPAddresses())
                    {
                        if (!IsIPAddressAllowed(ipAddress))
                        {
                            ips.Add(ipAddress);
                        }
                    }
                }
                foreach (MemoryFirewallRuleRanges rule in blockRulesRanges.Values)
                {
                    foreach (IPAddressRange range in rule.EnumerateIPAddressesRanges())
                    {
                        if (range.Single)
                        {
                            if (!IsIPAddressAllowed(range.Begin, out _))
                            {
                                ips.Add(range.Begin.ToString());
                            }
                        }
                        else
                        {
                            ips.Add(range.ToString());
                        }
                    }
                }
            }
            return ips;
        }

        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            lock (this)
            {
                List<IPAddressRange> results = new();
                string prefix = ScrubRuleNamePrefix(BlockRulePrefix, ruleNamePrefix);
                foreach (var rule in blockRules)
                {
                    if (string.IsNullOrWhiteSpace(ruleNamePrefix) ||
                        rule.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        results.AddRange(rule.Value.EnumerateIPAddressesRanges());
                    }
                }
                foreach (var rule in blockRulesRanges)
                {
                    if (string.IsNullOrWhiteSpace(ruleNamePrefix) ||
                        rule.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        results.AddRange(rule.Value.EnumerateIPAddressesRanges());
                    }
                }

                prefix = ScrubRuleNamePrefix(AllowRulePrefix, ruleNamePrefix);
                foreach (var rule in allowRuleRanges)
                {
                    if (string.IsNullOrWhiteSpace(ruleNamePrefix) ||
                        rule.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        results.AddRange(rule.Value.EnumerateIPAddressesRanges());
                    }
                }
                if (string.IsNullOrWhiteSpace(ruleNamePrefix) ||
                    allowRule.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    results.AddRange(allowRule.EnumerateIPAddressesRanges());
                }
                return results;
            }
        }

        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            lock (this)
            {
                string prefix1 = ScrubRuleNamePrefix(AllowRulePrefix, ruleNamePrefix);
                string prefix2 = ScrubRuleNamePrefix(BlockRulePrefix, ruleNamePrefix);
                string prefix3 = ScrubRuleNamePrefix(RulePrefix, ruleNamePrefix);
                IEnumerable<string> ruleNames = new string[] { AllowRuleName }.Union(allowRuleRanges.Keys).Union(blockRules.Keys).Union(blockRulesRanges.Keys);
                return ruleNames.Where(r => string.IsNullOrWhiteSpace(ruleNamePrefix) ||
                    r.StartsWith(prefix1, StringComparison.OrdinalIgnoreCase) ||
                    r.StartsWith(prefix2, StringComparison.OrdinalIgnoreCase) ||
                    r.StartsWith(prefix3, StringComparison.OrdinalIgnoreCase)).ToArray();
            }
        }


        public override bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                return false;
            }
            return IsIPAddressAllowed(ipAddressObj, out _, port);
        }

        public bool IsIPAddressAllowed(System.Net.IPAddress ipAddressObj, out string ruleName, int port = -1)
        {
            lock (this)
            {
                if (allowRule.Contains(ipAddressObj, port))
                {
                    ruleName = allowRule.Name;
                    return true;
                }

                foreach (MemoryFirewallRuleRanges ranges in allowRuleRanges.Values)
                {
                    if (ranges.Contains(ipAddressObj, port))
                    {
                        ruleName = ranges.Name;
                        return true;
                    }
                }
            }
            ruleName = null;
            return false;
        }

        public bool IsIPAddressBlocked(string ipAddress, int port = -1)
        {
            return IsIPAddressBlocked(ipAddress, out _, port);
        }

        public bool IsIPAddressBlocked(System.Net.IPAddress ipAddressObj, out string ruleName, int port = -1)
        {
            lock (this)
            {
                if (IsIPAddressAllowed(ipAddressObj, out ruleName, port))
                {
                    return false;
                }
                else if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint ipv4 = ipAddressObj.ToUInt32();
                    foreach (KeyValuePair<string, MemoryFirewallRule> rule in blockRules)
                    {
                        if (rule.Value.Contains(ipv4, port))
                        {
                            ruleName = rule.Key;
                            return true;
                        }
                    }
                    foreach (KeyValuePair<string, MemoryFirewallRuleRanges> rule in blockRulesRanges)
                    {
                        if (rule.Value.Contains(ipv4, port))
                        {
                            ruleName = rule.Key;
                            return true;
                        }
                    }
                }
                else
                {
                    UInt128 ipv6 = ipAddressObj.ToUInt128();
                    foreach (KeyValuePair<string, MemoryFirewallRule> rule in blockRules)
                    {
                        if (rule.Value.Contains(ipv6, port))
                        {
                            ruleName = rule.Key;
                            return true;
                        }
                    }
                    foreach (KeyValuePair<string, MemoryFirewallRuleRanges> rule in blockRulesRanges)
                    {
                        if (rule.Value.Contains(ipv6, port))
                        {
                            ruleName = rule.Key;
                            return true;
                        }
                    }
                }
            }
            ruleName = null;
            return false;
        }

        public override bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            if (!System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj))
            {
                ruleName = null;
                return false;
            }
            return IsIPAddressBlocked(ipAddressObj, out ruleName, port);
        }

        public override void Truncate()
        {
            lock (this)
            {
                blockRules.Clear();
                blockRulesRanges.Clear();
                allowRule.SetIPAddresses(Array.Empty<string>(), null);
            }
        }
    }
}
