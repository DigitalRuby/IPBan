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
            private readonly List<IPV4Range> ipv4 = new List<IPV4Range>();
            private readonly List<IPV6Range> ipv6 = new List<IPV6Range>();
            private readonly List<PortRange> portRanges;

            public IEnumerable<string> IPV4 => ipv4.Select(r => r.ToIPAddressRange().ToCidrString());
            public IEnumerable<string> IPV6 => ipv6.Select(r => r.ToIPAddressRange().ToCidrString());
            public IEnumerable<string> PortRanges => portRanges.Select(r => r.ToString());

            public bool Block { get; }

            public MemoryFirewallRuleRanges(List<IPAddressRange> ipRanges, List<PortRange> allowedPorts, bool block)
            {
                allowedPorts ??= new List<PortRange>(0);
                Block = block;
                foreach (IPAddressRange range in ipRanges)
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

            public IEnumerable<IPAddressRange> EnumerateIPAddresses()
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
            private readonly HashSet<uint> ipv4 = new HashSet<uint>();
            private readonly HashSet<UInt128> ipv6 = new HashSet<UInt128>();

            public IEnumerable<string> IPV4 => ipv4.Select(i => i.ToIPAddress().ToString());
            public IEnumerable<string> IPV6 => ipv6.Select(i => i.ToIPAddress().ToString());

            public bool Block { get; }

            public MemoryFirewallRule(bool block)
            {
                Block = block;
            }

            public void SetIPAddresses(IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowPorts)
            {
                ipv4.Clear();
                ipv6.Clear();
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
            }

#pragma warning disable IDE0060 // Remove unused parameter
            public void AddIPAddressesDelta(IEnumerable<IPBanFirewallIPAddressDelta> deltas, IEnumerable<PortRange> allowPorts = null)
#pragma warning restore IDE0060 // Remove unused parameter
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

            public bool Contains(System.Net.IPAddress ipAddressObj)
            {
                if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ipv4.Contains(ipAddressObj.ToUInt32());
                }
                return ipv6.Contains(ipAddressObj.ToUInt128());
            }

            public bool Contains(string ipAddress)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                {
                    return Contains(ipAddressObj);
                }
                return false;
            }

            public bool Contains(uint ipv4UInt)
            {
                return ipv4.Contains(ipv4UInt);
            }

            public bool Contains(UInt128 ipv6UInt128)
            {
                return ipv6.Contains(ipv6UInt128);
            }
        }

        private readonly Dictionary<string, MemoryFirewallRuleRanges> blockRulesRanges = new Dictionary<string, MemoryFirewallRuleRanges>();
        private readonly Dictionary<string, MemoryFirewallRule> blockRules = new Dictionary<string, MemoryFirewallRule>();
        private readonly MemoryFirewallRule allowRule = new MemoryFirewallRule(false);
        private readonly Dictionary<string, MemoryFirewallRuleRanges> allowRuleRanges = new Dictionary<string, MemoryFirewallRuleRanges>();

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
                    IEnumerable<KeyValuePair<string, IMemoryFirewallRule>> allowRules = new KeyValuePair<string, IMemoryFirewallRule>[] { new KeyValuePair<string, IMemoryFirewallRule>("DefaultAllow", allowRule) };
                    return blockRules
                        .Select(kv => new KeyValuePair<string, IMemoryFirewallRule>(kv.Key, kv.Value))
                        .Union(allowRules)
                        .ToArray();
                }
            }
        }

        private bool IsIPAddressAllowed(System.Net.IPAddress ipAddressObj, int port = -1)
        {
            lock (this)
            {
                if (allowRule.Contains(ipAddressObj))
                {
                    return true;
                }

                foreach (MemoryFirewallRuleRanges ranges in allowRuleRanges.Values)
                {
                    if (ranges.Contains(ipAddressObj, port))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private string ScrubRuleNamePrefix(string ruleNamePrefix)
        {
            if (string.IsNullOrWhiteSpace(ruleNamePrefix))
            {
                ruleNamePrefix = "Block";
            }
            // in memory firewall does not have a count limit per rule, so remove the trailing underscore if any
            return (RulePrefix + (ruleNamePrefix ?? string.Empty)).Trim('_');
        }

        protected override void OnDispose()
        {
            base.OnDispose();
            Truncate();
        }

        public IPBanMemoryFirewall(string rulePrefix = null) : base(rulePrefix)
        {
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
            var allowedIPList = ipAddresses.Select(i => IPAddressRange.Parse(i)).ToList();
            var allowedPortList = allowedPorts?.ToList();
            lock (this)
            {
                allowRuleRanges[ruleNamePrefix] = new MemoryFirewallRuleRanges(allowedIPList, allowedPortList, false); 
            }
            return Task.FromResult<bool>(true);
        }

        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            string ruleName = ScrubRuleNamePrefix(ruleNamePrefix);
            lock (this)
            {
                if (!blockRules.TryGetValue(ruleName, out MemoryFirewallRule rule))
                {
                    blockRules[ruleName] = rule = new MemoryFirewallRule(true);
                }
                rule.SetIPAddresses(ipAddresses, allowedPorts);
            }
            return Task.FromResult<bool>(true);
        }

        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            string ruleName = ScrubRuleNamePrefix(ruleNamePrefix);
            lock (this)
            {
                if (!blockRules.TryGetValue(ruleName, out MemoryFirewallRule rule))
                {
                    blockRules[ruleName] = rule = new MemoryFirewallRule(true);
                }
                rule.AddIPAddressesDelta(ipAddresses, allowedPorts);
            }
            return Task.FromResult(true);
        }

        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // for performance, ranges is assumed to be sorted
            ruleNamePrefix = ScrubRuleNamePrefix(ruleNamePrefix);
            List<IPAddressRange> rangesList = new List<IPAddressRange>(ranges);
            var portList = allowedPorts?.ToList();
            lock (this)
            {
                blockRulesRanges[ruleNamePrefix] = new MemoryFirewallRuleRanges(rangesList, portList, true);
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
                return allowRule.EnumerateIPAddresses().ToArray();
            }
        }

        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            List<string> ips = new List<string>();
            lock (this)
            {
                foreach (MemoryFirewallRule rule in blockRules.Values)
                {
                    foreach (string ipAddress in rule.EnumerateIPAddresses())
                    {
                        if (!allowRule.Contains(ipAddress))
                        {
                            ips.Add(ipAddress);
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
                string prefix = ScrubRuleNamePrefix(ruleNamePrefix);
                if (blockRules.TryGetValue(prefix, out MemoryFirewallRule rule))
                {
                    return rule.EnumerateIPAddressesRanges().ToArray();
                }
                else if (blockRulesRanges.TryGetValue(prefix, out MemoryFirewallRuleRanges ruleRanges))
                {
                    return ruleRanges.EnumerateIPAddresses().ToArray();
                }
                else if (prefix.StartsWith(RulePrefix + "Allow", StringComparison.OrdinalIgnoreCase))
                {
                    return allowRule.EnumerateIPAddressesRanges().ToArray();
                }
                return Array.Empty<IPAddressRange>();
            }
        }

        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            List<string> names = new List<string>();
            lock (this)
            {
                string prefix = ScrubRuleNamePrefix(ruleNamePrefix);
                foreach (string key in blockRules.Keys.Union(blockRulesRanges.Keys).Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    names.Add(key);
                }
                if (RulePrefix.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                    RulePrefix.StartsWith(prefix + "Allow", StringComparison.OrdinalIgnoreCase))
                {
                    names.Add(RulePrefix + "Allow");
                }
            }
            return names;
        }


        public override bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                return false;
            }
            return IsIPAddressAllowed(ipAddressObj);
        }

        public bool IsIPAddressBlocked(string ipAddress, int port = -1)
        {
            return IsIPAddressBlocked(ipAddress, out _, port);
        }

        public bool IsIPAddressBlocked(System.Net.IPAddress ipAddressObj, out string ruleName, int port = -1)
        {
            lock (this)
            {
                if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint ipv4 = ipAddressObj.ToUInt32();
                    foreach (KeyValuePair<string, MemoryFirewallRule> rule in blockRules)
                    {
                        if (rule.Value.Contains(ipv4))
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
                        if (rule.Value.Contains(ipv6))
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
            ruleName = null;

            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj) || IsIPAddressAllowed(ipAddressObj))
            {
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
