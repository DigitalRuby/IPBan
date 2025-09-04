/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// In memory firewall that persists rules to disk. This is not meant to be used directly but rather to be used inside of other firewall implementations.
    /// This class is thread safe.
    /// </summary>
    [RequiredOperatingSystemAttribute(null, Priority = -99)] // low priority, basically any other firewall is preferred unless this one is explicitly specified in the config
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public class IPBanMemoryFirewall : IPBanBaseFirewall
    {
        /// <summary>
        /// Memory firewall rule ranges interface
        /// </summary>
        public interface IMemoryFirewallRuleRanges
        {
            /// <summary>
            /// IPV4 ranges
            /// </summary>
            IEnumerable<string> IPV4Strings { get; }

            /// <summary>
            /// IPV6 ranges
            /// </summary>
            IEnumerable<string> IPV6Strings { get; }

            /// <summary>
            /// Port ranges, empty for none
            /// </summary>
            IEnumerable<string> PortRangeStrings { get; }

            /// <summary>
            /// True to block, false to allow
            /// </summary>
            bool Block { get; }

            /// <summary>
            /// Get count of entries
            /// </summary>
            /// <returns>Count</returns>
            int GetCount();
        }

        /// <summary>
        /// Memory firewall rule interface
        /// </summary>
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

            /// <summary>
            /// Get count of entries
            /// </summary>
            /// <returns>Count</returns>
            int GetCount();
        }

        private class MemoryFirewallRuleRanges : IComparer<IPV4Range>, IComparer<IPV6Range>, IMemoryFirewallRuleRanges
        {
            private readonly List<IPV4Range> ipv4 = [];
            private readonly List<IPV6Range> ipv6 = [];
            internal readonly PortRange[] portRanges = [];

            public IEnumerable<string> IPV4Strings => ipv4.Select(r => r.ToIPAddressRange().ToString());
            public IEnumerable<string> IPV6Strings => ipv6.Select(r => r.ToIPAddressRange().ToString());
            public IEnumerable<string> PortRangeStrings => portRanges.Select(r => r.ToString());
            public string Ports => string.Join(',', PortRangeStrings);

            public bool Block { get; }

            public string Name { get; }

            public MemoryFirewallRuleRanges(IEnumerable<IPAddressRange> ipRanges, IReadOnlyCollection<PortRange> allowPorts, bool block, string name)
            {
                Block = block;
                Name = name;

                List<IPAddressRange> ipRangesSorted = [.. ipRanges];
                ipRangesSorted.Sort();
                foreach (IPAddressRange range in ipRangesSorted)
                {
                    if (range.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        ipv4.Add(new IPV4Range(range));
                    }
                    else
                    {
                        ipv6.Add(new IPV6Range(range));
                    }
                }
                ipv4.TrimExcess();
                ipv6.TrimExcess();

                if (allowPorts is not null && allowPorts.Count != 0)
                {
                    if (block)
                    {
                        // invert allow ports to block ports
                        var invertedPorts = IPBanFirewallUtility.InvertPortRanges(allowPorts);
                        portRanges = [.. invertedPorts];
                    }
                    else
                    {
                        portRanges = [.. allowPorts];
                    }
                }
            }

            public void Add(IEnumerable<IPAddressRange> ipRanges)
            {
                List<IPAddressRange> ipRangesSorted = [.. ipRanges];
                foreach (IPAddressRange range in ipRangesSorted)
                {
                    // binary search in the list and insert the ip where it belongs (or at the end if not found)
                    // note: there could be duplicates, but that's ok, this method is really only called during testing iptables
                    if (range.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var newRange = new IPV4Range(range);
                        int pos = ipv4.BinarySearch(newRange, this);
                        if (pos < 0)
                        {
                            ipv4.Insert(~pos, newRange);
                        }
                    }
                    else
                    {
                        var newRange = new IPV6Range(range);
                        int pos = ipv6.BinarySearch(newRange, this);
                        if (pos < 0)
                        {
                            ipv6.Insert(~pos, newRange);
                        }
                    }
                }
                ipv4.TrimExcess();
                ipv6.TrimExcess();
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
                bool foundPort = port < 1 || portRanges.Length == 0 || portRanges.Any(p => p.Contains(port));
                return (foundPort && ipv4.BinarySearch(new IPV4Range(ipAddress, ipAddress), this) >= 0);
            }

            public bool Contains(UInt128 ipAddress, int port)
            {
                bool foundPort = port < 1 || portRanges.Length == 0 || portRanges.Any(p => p.Contains(port));
                return (foundPort && ipv6.BinarySearch(new IPV6Range(ipAddress, ipAddress), this) >= 0);
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

            /// <summary>
            /// Get count of entries
            /// </summary>
            /// <returns>Count</returns>
            public int GetCount() => ipv4.Count + ipv6.Count;
        }

        private class MemoryFirewallRule(bool block, string name) : IMemoryFirewallRule
        {
            private readonly HashSet<uint> ipv4 = [];
            private readonly HashSet<UInt128> ipv6 = [];
            private readonly List<PortRange> ports = [];

            public IEnumerable<string> IPV4 => ipv4.Select(i => i.ToIPAddress().ToString());
            public IEnumerable<string> IPV6 => ipv6.Select(i => i.ToIPAddress().ToString());
            public string Ports => string.Join(",", ports.Select(p => p.ToString()));

            public bool Block { get; } = block;

            public string Name { get; } = name;

            public void SetIPAddresses(IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowPorts)
            {
                ipv4.Clear();
                ipv6.Clear();
                this.ports.Clear();

                if (Block)
                {
                    // invert allow ports to block ports
                    allowPorts = IPBanFirewallUtility.InvertPortRanges(allowPorts);
                }

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
                foreach (var port in IPBanFirewallUtility.GetPortRangesForRule(allowPorts, Block))
                {
                    this.ports.Add(port);
                }
            }

            public void AddIPAddressesDelta(IEnumerable<IPBanFirewallIPAddressDelta> deltas, IEnumerable<PortRange> allowPorts = null)
            {
                if (Block)
                {
                    // invert allow ports to block ports
                    allowPorts = IPBanFirewallUtility.InvertPortRanges(allowPorts);
                }

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
                this.ports.Clear();
                if (allowPorts is not null)
                {
                    this.ports.AddRange(allowPorts);
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

            public bool ContainsIP(System.Net.IPAddress ipAddressObj, int port)
            {
                if (!ContainsPort(port))
                {
                    return false;
                }
                else if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ipv4.Contains(ipAddressObj.ToUInt32());
                }
                return ipv6.Contains(ipAddressObj.ToUInt128());
            }

            public bool ContainsIP(string ipAddress, int port)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                {
                    return ContainsIP(ipAddressObj, port);
                }
                return false;
            }

            public bool ContainsIP4(uint ipv4UInt, int port)
            {
                return ContainsPort(port) && ipv4.Contains(ipv4UInt);
            }

            public bool ContainsIP6(UInt128 ipv6UInt128, int port)
            {
                return ContainsPort(port) && ipv6.Contains(ipv6UInt128);
            }

            public bool ContainsPort(int port)
            {
                return (port < 1 || ports.Count == 0 || ports.Any(p => p.Contains(port)));
            }

            public int GetCount() => ipv4.Count + ipv6.Count;
        }

        private readonly Dictionary<string, MemoryFirewallRule> blockRules = [];
        private readonly Dictionary<string, MemoryFirewallRuleRanges> blockRulesRanges = [];
        private readonly MemoryFirewallRule allowRule;
        private readonly Dictionary<string, MemoryFirewallRuleRanges> allowRuleRanges = [];

        /// <inheritdoc />
        public override string ToString()
        {
            StringWriter s = new();

            foreach (var kv in blockRules)
            {
                s.WriteLine("Block rule: {0}, Count: {1}, IPs: {2}, Ports: {3}",
                    kv.Key, kv.Value.GetCount(), string.Join(", ", kv.Value.IPV4.Concat(kv.Value.IPV6)), kv.Value.Ports);
            }
            foreach (var kv in blockRulesRanges)
            {
                s.WriteLine("Block rule ranges: {0}, Count: {1}, IPs: {2}, Ports: {3}",
                    kv.Key, kv.Value.GetCount(), string.Join(", ", kv.Value.IPV4Strings.Concat(kv.Value.IPV6Strings)), kv.Value.Ports);
            }
            s.WriteLine("Allow rule: {0}, Count: {1}, IPs: {2}, Ports: {3}",
                allowRule.Name, allowRule.GetCount(), string.Join(", ", allowRule.IPV4.Concat(allowRule.IPV6)), allowRule.Ports);
            foreach (var kv in allowRuleRanges)
            {
                s.WriteLine("Allow rule ranges: {0}, Count: {1}, IPs: {2}, Ports: {3}",
                    kv.Key, kv.Value.GetCount(), string.Join(", ", kv.Value.IPV4Strings.Concat(kv.Value.IPV6Strings)), kv.Value.Ports);
            }

            return s.ToString();
        }

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
                    IEnumerable<KeyValuePair<string, IMemoryFirewallRule>> allowRules =
                    [
                        new(allowRule.Name, allowRule)
                    ];
                    return blockRules
                        .Select(kv => new KeyValuePair<string, IMemoryFirewallRule>(kv.Key, kv.Value))
                        .Union(allowRules)
                        .ToArray();
                }
            }
        }

        private string ScrubRuleNamePrefix(string prefix, string ruleNamePrefix)
        {
            ruleNamePrefix ??= string.Empty;

            if (!string.IsNullOrWhiteSpace(RulePrefix))
            {
                // remove prefix if it exists
                if (ruleNamePrefix.StartsWith(RulePrefix))
                {
                    ruleNamePrefix = ruleNamePrefix[RulePrefix.Length..];
                }
                if (ruleNamePrefix.StartsWith(prefix))
                {
                    ruleNamePrefix = ruleNamePrefix[prefix.Length..];
                }

                // in memory firewall does not have a count limit per rule, so remove the trailing underscore if any
                return (prefix + ruleNamePrefix).Trim('_');
            }

            return ruleNamePrefix;
        }

        /// <inheritdoc />
        protected override void OnDispose()
        {
            base.OnDispose();
            Truncate();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public IPBanMemoryFirewall(string rulePrefix = null) : base(rulePrefix)
        {
            allowRule = new MemoryFirewallRule(false, AllowRulePrefix + "0");
        }

        /// <inheritdoc />
        public override Task Update(CancellationToken cancelToken)
        {
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override IPBanMemoryFirewall Compile() => this;

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                allowRule.SetIPAddresses(ipAddresses, null);
            }
            return Task.FromResult<bool>(true);
        }

        /// <inheritdoc />
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

        /// <inheritdoc />
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

        /// <inheritdoc />
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

        /// <inheritdoc />
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

        /// <inheritdoc />
        public override bool DeleteRule(string ruleName)
        {
            lock (this)
            {
                return blockRules.Remove(ruleName) || blockRulesRanges.Remove(ruleName);
            }
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses(string ruleNamePrefix = null)
        {
            lock (this)
            {
                List<string> ips = [.. allowRule.EnumerateIPAddresses()];
                foreach (var rule in allowRuleRanges.Where(r => ruleNamePrefix is null || r.Key.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase)))
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

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses(string ruleNamePrefix = null)
        {
            List<string> ips = [];
            lock (this)
            {
                foreach (MemoryFirewallRule rule in blockRules.Values.Where(r => ruleNamePrefix is null || r.Name.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase)))
                {
                    foreach (string ipAddress in rule.EnumerateIPAddresses())
                    {
                        if (IPAddress.TryParse(ipAddress, out var ipAddressObj) &&
                            !IsIPAddressAllowedInternal(ipAddressObj, out _))
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
                            if (!IsIPAddressAllowedInternal(range.Begin, out _))
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

        /// <inheritdoc />
        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            lock (this)
            {
                List<IPAddressRange> results = [];
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

        /// <inheritdoc />
        public override string GetPorts(string ruleName)
        {
            if (blockRules.TryGetValue(ruleName, out var rule))
            {
                return rule.Ports;
            }
            else if (blockRulesRanges.TryGetValue(ruleName, out var ruleRanges))
            {
                return ruleRanges.Ports;
            }
            else if (!allowRuleRanges.TryGetValue(ruleName, out ruleRanges))
            {
                return ruleRanges.Ports;
            }
            else if (allowRule.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase))
            {
                return allowRule.Ports;
            }
            return null;
        }

        /// <inheritdoc />
        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            lock (this)
            {
                string prefix1 = ScrubRuleNamePrefix(AllowRulePrefix, ruleNamePrefix);
                string prefix2 = ScrubRuleNamePrefix(BlockRulePrefix, ruleNamePrefix);
                string prefix3 = ScrubRuleNamePrefix(RulePrefix, ruleNamePrefix);
                IEnumerable<string> ruleNames = new string[] { AllowRulePrefix + "0" }.Union(allowRuleRanges.Keys).Union(blockRules.Keys).Union(blockRulesRanges.Keys);
                return ruleNames.Where(r => string.IsNullOrWhiteSpace(ruleNamePrefix) ||
                    r.StartsWith(prefix1, StringComparison.OrdinalIgnoreCase) ||
                    r.StartsWith(prefix2, StringComparison.OrdinalIgnoreCase) ||
                    r.StartsWith(prefix3, StringComparison.OrdinalIgnoreCase)).ToArray();
            }
        }

        /// <inheritdoc />
        public bool IsIPAddressAllowed(string ipAddress, int port = 0)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                return false;
            }
            return IsIPAddressAllowed(ipAddressObj, out _, port);
        }

        /// <summary>
        /// Check if ip is allowed
        /// </summary>
        /// <param name="ipAddressObj">IP address</param>
        /// <param name="ruleName">Receives rule name if found</param>
        /// <param name="port">Port</param>
        /// <returns>True if ip is allowed</returns>
        public bool IsIPAddressAllowed(System.Net.IPAddress ipAddressObj, out string ruleName, int port = 0)
        {
            lock (this)
            {
                if (allowRule.ContainsIP(ipAddressObj, port))
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

        /// <summary>
        /// Check if ip is blocked
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="port">Port</param>
        /// <returns>True if ip is blocked</returns>
        public bool IsIPAddressBlocked(string ipAddress, int port = 0)
        {
            return IsIPAddressBlocked(ipAddress, out _, port);
        }

        /// <summary>
        /// Check if ip is blocked
        /// </summary>
        /// <param name="ipAddressObj">IP address</param>
        /// <param name="ruleName">Receive rule name if found</param>
        /// <param name="allowed">True if ip is in allow rule</param>
        /// <param name="port">Port</param>
        /// <returns>True if ip is blocked</returns>
        public bool IsIPAddressBlocked(System.Net.IPAddress ipAddressObj, out string ruleName, out bool allowed, int port = -1)
        {
            allowed = false;
            lock (this)
            {
                if (IsIPAddressAllowed(ipAddressObj, out ruleName, port))
                {
                    allowed = true;
                    return false;
                }
                else if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint ipv4 = ipAddressObj.ToUInt32();
                    foreach (KeyValuePair<string, MemoryFirewallRule> rule in blockRules)
                    {
                        if (rule.Value.ContainsIP4(ipv4, port))
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
                        if (rule.Value.ContainsIP6(ipv6, port))
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

        /// <inheritdoc />
        public bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = 0)
        {
            if (!IPAddressRange.TryParse(ipAddress, out var range))
            {
                ruleName = null;
                return false;
            }
            return IsIPAddressBlocked(range.Begin, out ruleName, out _, port);
        }

        /// <summary>
        /// Check if ip is allowed
        /// </summary>
        /// <param name="ipAddressObj">IP address</param>
        /// <param name="ruleName">Receives rule name if found</param>
        /// <param name="port">Port</param>
        /// <returns>True if ip is allowed</returns>
        private bool IsIPAddressAllowedInternal(System.Net.IPAddress ipAddressObj, out string ruleName, int port = 0)
        {
            lock (this)
            {
                if (allowRule.ContainsIP(ipAddressObj, port))
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

        /// <summary>
        /// Get count of entries for a rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>Count for that rule or 0 if no entries or rule not found</returns>
        public int GetCount(string ruleName)
        {
            lock (this)
            {
                if (allowRule.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    return allowRule.GetCount();
                }
                else if (allowRuleRanges.TryGetValue(ruleName, out var allowRuleRange))
                {
                    return allowRuleRange.GetCount();
                }
                else if (blockRules.TryGetValue(ruleName, out var blockRule))
                {
                    return blockRule.GetCount();
                }
                else if (blockRulesRanges.TryGetValue(ruleName, out var blockRuleRange))
                {
                    return blockRuleRange.GetCount();
                }
            }
            return 0;
        }

        /// <summary>
        /// Check if ip is blocked
        /// </summary>
        /// <param name="ipAddressObj">IP address</param>
        /// <param name="ruleName">Receive rule name if found</param>
        /// <param name="allowed">True if ip is in allow rule</param>
        /// <param name="port">Port</param>
        /// <returns>True if ip is blocked</returns>
        private bool IsIPAddressBlockedInternal(System.Net.IPAddress ipAddressObj, out string ruleName, out bool allowed, int port = 0)
        {
            allowed = false;
            lock (this)
            {
                if (IsIPAddressAllowedInternal(ipAddressObj, out ruleName, port))
                {
                    allowed = true;
                    return false;
                }
                else if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint ipv4 = ipAddressObj.ToUInt32();
                    foreach (KeyValuePair<string, MemoryFirewallRule> rule in blockRules)
                    {
                        if (rule.Value.ContainsIP4(ipv4, port))
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
                        if (rule.Value.ContainsIP6(ipv6, port))
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

        /// <inheritdoc />
        public override void Truncate()
        {
            lock (this)
            {
                blockRules.Clear();
                blockRulesRanges.Clear();
                allowRule.SetIPAddresses([], null);
            }
        }

        /// <summary>
        /// Merge another memory firewall into this one
        /// </summary>
        /// <param name="mem">Memory firewall to merge</param>
        public void Merge(IPBanMemoryFirewall mem)
        {
            lock (this)
            {
                foreach (var kv in mem.blockRules)
                {
                    if (!blockRules.TryGetValue(kv.Key, out var rule))
                    {
                        blockRules[kv.Key] = rule = new MemoryFirewallRule(true, kv.Key);
                    }
                    rule.AddIPAddressesDelta(kv.Value.EnumerateIPAddresses().Select(ip => new IPBanFirewallIPAddressDelta(true, ip)));
                }
                foreach (var kv in mem.blockRulesRanges)
                {
                    if (!blockRulesRanges.TryGetValue(kv.Key, out var rule))
                    {
                        blockRulesRanges[kv.Key] = rule = new MemoryFirewallRuleRanges([], kv.Value.portRanges, true, kv.Key);
                    }
                    rule.Add(kv.Value.EnumerateIPAddressesRanges());
                }
                allowRule.AddIPAddressesDelta(mem.allowRule.EnumerateIPAddresses().Select(ip => new IPBanFirewallIPAddressDelta(true, ip)));
                foreach (var kv in mem.allowRuleRanges)
                {
                    if (!allowRuleRanges.TryGetValue(kv.Key, out var rule))
                    {
                        allowRuleRanges[kv.Key] = rule = new MemoryFirewallRuleRanges([], kv.Value.portRanges, false, kv.Key);
                    }
                    rule.Add(kv.Value.EnumerateIPAddressesRanges());
                }
            }
        }
    }
}
