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

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Linux firewall implementation using iptables
    /// </summary>
    [RequiredOperatingSystem(OSUtility.Linux,
        Priority = 1,
        PriorityEnvironmentVariable = "IPBanPro_LinuxFirewallIPTablesPriority")]
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public class IPBanLinuxFirewallIPTables : IPBanLinuxBaseFirewallIPTables
    {
        /// <summary>
        /// Linux Firewall iptables for IPV6, is wrapped inside IPBanLinuxFirewallIPTables
        /// </summary>
        private sealed class IPBanLinuxFirewallIPTables6(string rulePrefix) : IPBanLinuxBaseFirewallIPTables(rulePrefix + "6_")
        {
            protected override bool IsIPV4 => false;
            protected override string INetFamily => IPBanLinuxIPSetIPTables.INetFamilyIPV6;
            protected override string SetSuffix => ".set6";
            protected override string TableSuffix => ".tbl6";
            protected override string IpTablesProcess => Ip6TablesProcess;
        }

        private readonly IPBanLinuxFirewallIPTables6 firewall6;

        /// <inheritdoc />
        protected override void OnDispose()
        {
            base.OnDispose();
            firewall6.Dispose();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public IPBanLinuxFirewallIPTables(string rulePrefix) : base(rulePrefix)
        {
            firewall6 = new IPBanLinuxFirewallIPTables6(RulePrefix);

            // ensure legacy iptables are used
            IPBanFirewallUtility.RunProcess("update-alternatives", null, null, "--set", "iptables", "/usr/sbin/iptables-legacy");
            IPBanFirewallUtility.RunProcess("update-alternatives", null, null, "--set", "ip6tables", "/usr/sbin/ip6tables-legacy");
        }

        /// <inheritdoc />
        public override async Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            IEnumerable<string> ipv4 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<string> ipv6 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = await base.BlockIPAddresses(ruleNamePrefix, ipv4, allowedPorts, cancelToken);
            if (result)
            {
                result = await firewall6.BlockIPAddresses(ruleNamePrefix, ipv6, allowedPorts, cancelToken);
            }
            return result;
        }

        /// <inheritdoc />
        public override async Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            List<IPBanFirewallIPAddressDelta> deltas4 = new(ipAddresses.Where(i => IPAddress.Parse(i.IPAddress).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));
            List<IPBanFirewallIPAddressDelta> deltas6 = new(ipAddresses.Where(i => IPAddress.Parse(i.IPAddress).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6));
            bool result = await base.BlockIPAddressesDelta(ruleNamePrefix, deltas4, allowedPorts, cancelToken);
            if (result)
            {
                result = await firewall6.BlockIPAddressesDelta(ruleNamePrefix, deltas6, allowedPorts, cancelToken);
            }
            return result;
        }

        /// <inheritdoc />
        public override async Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            IEnumerable<IPAddressRange> ipv4 = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && i.End.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<IPAddressRange> ipv6 = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && i.End.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = await base.BlockIPAddresses(ruleNamePrefix, ranges, allowedPorts, cancelToken);
            if (result)
            {
                result = await firewall6.BlockIPAddresses(ruleNamePrefix, ranges, allowedPorts, cancelToken);
            }
            return result;
        }

        /// <inheritdoc />
        public override async Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            IEnumerable<string> ipv4 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<string> ipv6 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = await base.AllowIPAddresses(ipv4, cancelToken);
            if (result)
            {
                result = await firewall6.AllowIPAddresses(ipv6, cancelToken);
            }
            return result;
        }

        /// <inheritdoc />
        public override async Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            IEnumerable<IPAddressRange> ipv4 = ipAddresses.Where(i => IPAddressRange.TryParse(i, out IPAddressRange obj) && obj.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<IPAddressRange> ipv6 = ipAddresses.Where(i => IPAddressRange.TryParse(i, out IPAddressRange obj) && obj.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = await base.AllowIPAddresses(ruleNamePrefix, ipv4, allowedPorts, cancelToken);
            if (result)
            {
                result = await firewall6.AllowIPAddresses(ruleNamePrefix, ipv6, allowedPorts, cancelToken);
            }
            return result;
        }

        /// <inheritdoc />
        public override string GetPorts(string ruleName)
        {
            return base.GetPorts(ruleName) ?? firewall6.GetPorts(ruleName);
        }

        /// <inheritdoc />
        public override void Truncate()
        {
            base.Truncate();
            firewall6.Truncate();
        }

        /// <inheritdoc />
        public override IPBanMemoryFirewall Compile()
        {
            var baseMem = base.Compile();
            var mem6 = firewall6.Compile();
            baseMem.Merge(mem6);
            return baseMem;
        }
    }
}
