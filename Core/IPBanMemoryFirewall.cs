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

        private class BlockRule : IComparer<IPV4Range>, IComparer<IPV6Range>
        {
            private readonly List<IPV4Range> ipv4 = new List<IPV4Range>();
            private readonly List<IPV6Range> ipv6 = new List<IPV6Range>();
            private readonly List<PortRange> allowPorts;

            public BlockRule(List<IPAddressRange> blockRanges, List<PortRange> allowPorts)
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
                        // conveniently a guid is 16 bytes and provides compare methods :)
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

            public bool ShouldBlockV4(uint ipAddress, int port)
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

            public bool ShouldBlockV6(UInt128 ipAddress, int port)
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

        private HashSet<uint> allowedIPAddressesV4 = new HashSet<uint>();
        private HashSet<UInt128> allowedIPAddressesV6 = new HashSet<UInt128>();
        private HashSet<uint> blockedIPAddressesV4 = new HashSet<uint>();
        private HashSet<UInt128> blockedIPAddressesV6 = new HashSet<UInt128>();
        private readonly ConcurrentDictionary<string, BlockRule> blockRules = new ConcurrentDictionary<string, BlockRule>();

        public string RulePrefix { get; set; }

        private string ScrubRuleNamePrefix(string ruleNamePrefix)
        {
            // in memory firewall does not have a count limit per rule, so remove the trailing underscore if any
            return RulePrefix + (ruleNamePrefix ?? string.Empty).Trim('_');
        }

        private void AssignIPAddresses(IEnumerable<string> ipAddresses, HashSet<uint> v4, HashSet<UInt128> v6)
        {
            foreach (string ipAddress in ipAddresses)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                {
                    if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        v4.Add(ipAddressObj.ToUInt32());
                    }
                    else
                    {
                        v6.Add(ipAddressObj.ToUInt128());
                    }
                }
            }
        }

        public void Update()
        {
        }

        public Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                AssignIPAddresses(ipAddresses, allowedIPAddressesV4, allowedIPAddressesV6);
            }
            return Task.FromResult<bool>(true);
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                AssignIPAddresses(ipAddresses, blockedIPAddressesV4, blockedIPAddressesV6);
            }
            return Task.FromResult<bool>(true);
        }

        public Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, CancellationToken cancelToken = default)
        {
            lock (this)
            {
                List<IPBanFirewallIPAddressDelta> deltas = new List<IPBanFirewallIPAddressDelta>(ipAddresses);
                foreach (IPBanFirewallIPAddressDelta delta in deltas)
                {
                    if (IPAddress.TryParse(delta.IPAddress, out IPAddress ip))
                    {
                        if (delta.Added)
                        {
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                blockedIPAddressesV4.Add(ip.ToUInt32());
                            }
                            else
                            {
                                blockedIPAddressesV6.Add(ip.ToUInt128());
                            }
                        }
                        else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            blockedIPAddressesV4.Remove(ip.ToUInt32());
                        }
                        else
                        {
                            blockedIPAddressesV6.Remove(ip.ToUInt128());
                        }
                    }
                }
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
                blockRules[ruleNamePrefix] = new BlockRule(rangesList, portList);
            }
            return Task.FromResult<bool>(true);
        }

        public bool DeleteRule(string ruleName)
        {
            lock (this)
            {
                return blockRules.TryRemove(ruleName, out _);
            }
        }

        public void Dispose()
        {
            lock (this)
            {
                allowedIPAddressesV4.Clear();
                allowedIPAddressesV6.Clear();
                blockedIPAddressesV4.Clear();
                blockedIPAddressesV6.Clear();
                blockRules.Clear();
            }
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            lock (this)
            {
                foreach (uint ipv4 in allowedIPAddressesV4)
                {
                    yield return ipv4.ToIPAddress().ToString();
                }
                foreach (UInt128 ipv6 in allowedIPAddressesV6)
                {
                    yield return ipv6.ToIPAddress().ToString();
                }
            }
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            lock (this)
            {
                return blockedIPAddressesV4.Where(i => !allowedIPAddressesV4.Contains(i)).Select(i => i.ToIPAddress().ToString())
                    .Union(blockedIPAddressesV6.Where(i => !allowedIPAddressesV6.Contains(i)).Select(i => i.ToIPAddress().ToString())).ToArray();
            }
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            lock (this)
            {
                ruleNamePrefix = ScrubRuleNamePrefix(ruleNamePrefix);
                if (ruleNamePrefix.StartsWith(RulePrefix + "0", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (uint ip in blockedIPAddressesV4)
                    {
                        yield return new IPAddressRange(ip.ToIPAddress());
                    }
                    foreach (UInt128 ip in blockedIPAddressesV6)
                    {
                        yield return new IPAddressRange(ip.ToIPAddress());
                    }
                }
                if (ruleNamePrefix.StartsWith(RulePrefix + "1", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (uint ip in allowedIPAddressesV4)
                    {
                        yield return new IPAddressRange(ip.ToIPAddress());
                    }
                    foreach (UInt128 ip in allowedIPAddressesV6)
                    {
                        yield return new IPAddressRange(ip.ToIPAddress());
                    }
                }
                foreach (string key in blockRules.Keys.Where(k => k.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase)))
                {
                    BlockRule rule = blockRules[key];
                    foreach (IPAddressRange range in rule.EnumerateIPAddresses())
                    {
                        yield return range;
                    }
                }
            }
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            lock (this)
            {
                ruleNamePrefix = ScrubRuleNamePrefix(ruleNamePrefix);
                if (ruleNamePrefix.StartsWith(RulePrefix + "0", StringComparison.OrdinalIgnoreCase))
                {
                    yield return RulePrefix + "0";
                }
                if (ruleNamePrefix.StartsWith(RulePrefix + "1", StringComparison.OrdinalIgnoreCase))
                {
                    yield return RulePrefix + "1";
                }
                foreach (string key in blockRules.Keys.Where(k => k.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return key;
                }
            }
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                return false;
            }

            lock (this)
            {
                if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return allowedIPAddressesV4.Contains(ipAddressObj.ToUInt32());
                }
                return allowedIPAddressesV6.Contains(ipAddressObj.ToUInt128());
            }
        }

        public bool IsIPAddressBlocked(string ipAddress, int port = -1)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
            {
                return false;
            }

            lock (this)
            {
                if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    uint ipv4 = ipAddressObj.ToUInt32();
                    if (allowedIPAddressesV4.Contains(ipv4))
                    {
                        return false;
                    }
                    else if (blockedIPAddressesV4.Contains(ipv4))
                    {
                        return true;
                    }
                    foreach (BlockRule rule in blockRules.Values)
                    {
                        if (rule.ShouldBlockV4(ipv4, port))
                        {
                            return true;
                        }
                    }
                }
                else
                {
                    UInt128 ipv6 = ipAddressObj.ToUInt128();
                    if (allowedIPAddressesV6.Contains(ipv6))
                    {
                        return false;
                    }
                    else if (blockedIPAddressesV6.Contains(ipv6))
                    {
                        return true;
                    }
                    foreach (BlockRule rule in blockRules.Values)
                    {
                        if (rule.ShouldBlockV6(ipv6, port))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public bool RuleExists(string ruleName)
        {
            if (ruleName == RulePrefix + "0")
            {
                return true;
            }

            lock (this)
            {
                return blockRules.ContainsKey(ruleName);
            }
        }

        public Task UnblockIPAddresses(IEnumerable<string> ipAddresses)
        {
            lock (this)
            {
                foreach (string ipAddress in ipAddresses)
                {
                    if (IPAddress.TryParse(ipAddress, out IPAddress ipAddressObj))
                    {
                        if (ipAddressObj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            blockedIPAddressesV4.Remove(ipAddressObj.ToUInt32());
                        }
                        else
                        {
                            blockedIPAddressesV6.Remove(ipAddressObj.ToUInt128());
                        }
                    }
                }
            }
            return Task.CompletedTask;
        }

        public void Truncate()
        {
            lock (this)
            {
                allowedIPAddressesV4.Clear();
                blockedIPAddressesV4.Clear();
                allowedIPAddressesV6.Clear();
                blockedIPAddressesV6.Clear();
                blockRules.Clear();
            }
        }
    }
}
