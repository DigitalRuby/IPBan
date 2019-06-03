using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.Caching;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// In memory firewall that persists rules to disk. This is not meant to be used directly but rather to be used inside of other firewall implementations.
    /// Use the IsIPAddressBlocked method in your firewall implementation / packet injection / etc.
    /// Also great for unit testing.
    /// This class is thread safe.
    /// </summary>
    [RequiredOperatingSystemAttribute(null, -99)] // low priority, basically any other firewall is preferred unless this one is explicitly specified in the config
    [CustomName("Memory")]
    public class IPBanMemoryFirewall : IIPBanFirewall
    {
        private struct IPV4Range
        {
            public uint Begin;
            public uint End;
        }

        private struct IPV6Range
        {
            public UInt128 Begin;
            public UInt128 End;
        }

        private class MemoryFirewallRuleRanges : IComparer<IPV4Range>, IComparer<IPV6Range>
        {
            private readonly List<IPV4Range> ipv4 = new List<IPV4Range>();
            private readonly List<IPV6Range> ipv6 = new List<IPV6Range>();
            private readonly List<PortRange> allowPorts;

            public MemoryFirewallRuleRanges(List<IPAddressRange> blockRanges, List<PortRange> allowPorts)
            {
                foreach (IPAddressRange range in blockRanges)
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
                this.allowPorts = allowPorts;
            }

            public bool Contains(uint ipAddress, int port)
            {
                foreach (PortRange range in allowPorts)
                {
                    if (port >= range.MinPort && port <= range.MaxPort)
                    {
                        return false;
                    }
                }
                return (ipv4.BinarySearch(new IPV4Range { Begin = ipAddress, End = ipAddress }, this) >= 0);
            }

            public bool Contains(UInt128 ipAddress, int port)
            {
                foreach (PortRange range in allowPorts)
                {
                    if (port >= range.MinPort && port <= range.MaxPort)
                    {
                        return false;
                    }
                }
                return (ipv6.BinarySearch(new IPV6Range { Begin = ipAddress, End = ipAddress }, this) >= 0);
            }

            public IEnumerable<IPAddressRange> EnumerateIPAddresses()
            {
                IPAddress ip1, ip2;
                foreach (IPV4Range range in ipv4)
                {
                    ip1 = range.Begin.ToIPAddress();
                    ip2 = range.End.ToIPAddress();
                    yield return new IPAddressRange(ip1, ip2);
                }
                foreach (IPV6Range range in ipv6)
                {
                    ip1 = range.Begin.ToIPAddress();
                    ip2 = range.End.ToIPAddress();
                    yield return new IPAddressRange(ip1, ip2);
                }
            }

            int IComparer<IPV4Range>.Compare(IPV4Range x, IPV4Range y)
            {
                int cmp = x.End.CompareTo(y.Begin);
                if (cmp < 0)
                {
                    return cmp;
                }
                cmp = x.Begin.CompareTo(y.End);
                if (cmp > 0)
                {
                    return cmp;
                }

                // inside range
                return 0;
            }

            int IComparer<IPV6Range>.Compare(IPV6Range x, IPV6Range y)
            {
                int cmp = x.End.CompareTo(y.Begin);
                if (cmp < 0)
                {
                    return cmp;
                }
                cmp = x.Begin.CompareTo(y.End);
                if (cmp > 0)
                {
                    return cmp;
                }

                // inside range
                return 0;
            }
        }

        private class MemoryFirewallRule
        {
            private readonly HashSet<uint> ipv4 = new HashSet<uint>();
            private readonly HashSet<UInt128> ipv6 = new HashSet<UInt128>();

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

            public void AddIPAddressesDelta(IEnumerable<IPBanFirewallIPAddressDelta> deltas, IEnumerable<PortRange> allowPorts)
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

            public bool Contains(string ipAddress)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                {
                    if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        return ipv4.Contains(ipAddressObj.ToUInt32());
                    }
                    return ipv6.Contains(ipAddressObj.ToUInt128());
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
        private readonly MemoryFirewallRule allowRule = new MemoryFirewallRule();

        public string RulePrefix { get; set; } = "IPBan_";

        private string ScrubRuleNamePrefix(string ruleNamePrefix)
        {
            if (string.IsNullOrWhiteSpace(ruleNamePrefix))
            {
                ruleNamePrefix = "Block";
            }
            // in memory firewall does not have a count limit per rule, so remove the trailing underscore if any
            return (RulePrefix + (ruleNamePrefix ?? string.Empty)).Trim('_');
        }

        public void Update()
        {
        }

        public Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                allowRule.SetIPAddresses(ipAddresses, null);
            }
            return Task.FromResult<bool>(true);
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                string ruleName = ScrubRuleNamePrefix(ruleNamePrefix);
                if (!blockRules.TryGetValue(ruleName, out MemoryFirewallRule rule))
                {
                    blockRules[ruleName] = rule = new MemoryFirewallRule();
                }
                rule.SetIPAddresses(ipAddresses, allowedPorts);
            }
            return Task.FromResult<bool>(true);
        }

        public Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                string ruleName = ScrubRuleNamePrefix(ruleNamePrefix);
                if (!blockRules.TryGetValue(ruleName, out MemoryFirewallRule rule))
                {
                    blockRules[ruleName] = rule = new MemoryFirewallRule();
                }
                rule.AddIPAddressesDelta(ipAddresses, allowedPorts);
            }
            return Task.FromResult(true);
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            // for performance, ranges is assumed to be sorted
            lock (this)
            {
                ruleNamePrefix = ScrubRuleNamePrefix(ruleNamePrefix);
                List<IPAddressRange> rangesList = new List<IPAddressRange>(ranges);
                List<PortRange> portList = new List<PortRange>(allowedPorts ?? new PortRange[0]);
                blockRulesRanges[ruleNamePrefix] = new MemoryFirewallRuleRanges(rangesList, portList);
            }
            return Task.FromResult<bool>(true);
        }

        public bool DeleteRule(string ruleName)
        {
            lock (this)
            {
                return blockRules.Remove(ruleName) || blockRulesRanges.Remove(ruleName);
            }
        }

        public void Dispose()
        {
            Truncate();
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            lock (this)
            {
                return allowRule.EnumerateIPAddresses();
            }
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            lock (this)
            {
                foreach (MemoryFirewallRule rule in blockRules.Values)
                {
                    foreach (string ipAddress in rule.EnumerateIPAddresses())
                    {
                        if (!allowRule.Contains(ipAddress))
                        {
                            yield return ipAddress;
                        }
                    }
                }
            }
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            lock (this)
            {
                string prefix = ScrubRuleNamePrefix(ruleNamePrefix);
                if (blockRules.TryGetValue(prefix, out MemoryFirewallRule rule))
                {
                    return rule.EnumerateIPAddressesRanges();
                }
                else if (blockRulesRanges.TryGetValue(prefix, out MemoryFirewallRuleRanges ruleRanges))
                {
                    return ruleRanges.EnumerateIPAddresses();
                }
                else if (prefix.StartsWith(RulePrefix + "Allow", StringComparison.OrdinalIgnoreCase))
                {
                    return allowRule.EnumerateIPAddressesRanges();
                }
                return new IPAddressRange[0];
            }
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            lock (this)
            {
                string prefix = ScrubRuleNamePrefix(ruleNamePrefix);
                foreach (string key in blockRules.Keys.Union(blockRulesRanges.Keys).Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return key;
                }
                if (RulePrefix.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                    RulePrefix.StartsWith(prefix + "Allow", StringComparison.OrdinalIgnoreCase))
                {
                    yield return RulePrefix + "Allow";
                }
            }
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            lock (this)
            {
                return allowRule.Contains(ipAddress);
            }
        }

        public bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            ruleName = null;

            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                return false;
            }

            lock (this)
            {
                if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint ipv4 = ipAddressObj.ToUInt32();
                    if (allowRule.Contains(ipv4))
                    {
                        return false;
                    }
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
                    if (allowRule.Contains(ipv6))
                    {
                        return false;
                    }
                    foreach(KeyValuePair<string, MemoryFirewallRule> rule in blockRules)
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
            return false;
        }

        public void Truncate()
        {
            lock (this)
            {
                blockRules.Clear();
                blockRulesRanges.Clear();
                allowRule.SetIPAddresses(new string[0], null);
            }
        }
    }
}
