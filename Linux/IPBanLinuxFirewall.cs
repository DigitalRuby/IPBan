/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    [RequiredOperatingSystem(IPBanOS.Linux)]
    [CustomName("Default")]
    public class IPBanLinuxFirewall : IPBanLinuxBaseFirewall
    {
        /// <summary>
        /// Linux Firewall for IPV6, is wrapped inside IPBanLinuxFirewall
        /// </summary>
        private class IPBanLinuxFirewall6 : IPBanLinuxBaseFirewall
        {
            protected override bool IsIPV4 => false;
            protected override string INetFamily => "inet6";
            protected override string SetSuffix => ".set6";
            protected override string TableSuffix => ".tbl6";
            protected override string IpTablesProcess => "ip6tables";
            protected override string RuleSuffix => "6_";

            public IPBanLinuxFirewall6(string rulePrefix = null) : base(rulePrefix)
            {
            }
        }

        private IPBanLinuxFirewall6 firewall6;

        protected override void OnDispose()
        {
            base.OnDispose();
            firewall6.Dispose();
        }

        protected internal override void SaveTableToDisk()
        {
            base.SaveTableToDisk();
            firewall6.SaveTableToDisk();
        }

        protected internal override void RestoreTablesFromDisk()
        {
            base.RestoreTablesFromDisk();
            firewall6.RestoreTablesFromDisk();
        }

        protected override void OnInitialize()
        {
            base.OnInitialize();
            firewall6 = new IPBanLinuxFirewall6(RulePrefix);
        }

        public IPBanLinuxFirewall(string rulePrefix = null) : base(rulePrefix) { }

        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            IEnumerable<string> ipv4 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<string> ipv6 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = base.BlockIPAddresses(ruleNamePrefix, ipv4, allowedPorts, cancelToken).Sync();
            if (result)
            {
                result = firewall6.BlockIPAddresses(ruleNamePrefix, ipv6, allowedPorts, cancelToken).Sync();
            }
            return Task.FromResult(result);
        }

        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            List<IPBanFirewallIPAddressDelta> deltas4 = new List<IPBanFirewallIPAddressDelta>(ipAddresses.Where(i => IPAddress.Parse(i.IPAddress).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));
            List<IPBanFirewallIPAddressDelta> deltas6 = new List<IPBanFirewallIPAddressDelta>(ipAddresses.Where(i => IPAddress.Parse(i.IPAddress).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6));
            bool result = base.BlockIPAddressesDelta(ruleNamePrefix, deltas4, allowedPorts, cancelToken).Sync();
            if (result)
            {
                result = firewall6.BlockIPAddressesDelta(ruleNamePrefix, deltas6, allowedPorts, cancelToken).Sync();
            }
            return Task.FromResult(result);
        }

        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            IEnumerable<IPAddressRange> ipv4 = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && i.End.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<IPAddressRange> ipv6 = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && i.End.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = base.BlockIPAddresses(ruleNamePrefix, ranges, allowedPorts, cancelToken).Sync();
            if (result)
            {
                result = firewall6.BlockIPAddresses(ruleNamePrefix, ranges, allowedPorts, cancelToken).Sync();
            }
            return Task.FromResult(result);
        }

        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            IEnumerable<string> ipv4 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            IEnumerable<string> ipv6 = ipAddresses.Where(i => IPAddress.TryParse(i, out IPAddress obj) && obj.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            bool result = base.AllowIPAddresses(ipv4, cancelToken).Sync();
            if (result)
            {
                result = firewall6.AllowIPAddresses(ipv6, cancelToken).Sync();
            }
            return Task.FromResult(result);
        }
    }
}

// https://linuxconfig.org/how-to-setup-ftp-server-on-ubuntu-18-04-bionic-beaver-with-vsftpd
// ipset create IPBanBlacklist iphash maxelem 1048576
// ipset destroy IPBanBlacklist // clear everything
// ipset -A IPBanBlacklist 10.10.10.10
// ipset -A IPBanBlacklist 10.10.10.11
// ipset save > file.txt
// ipset restore < file.txt
// iptables -A INPUT -m set --match-set IPBanBlacklist dst -j DROP
// iptables -F // clear all rules - this may break SSH permanently!
// iptables-save > file.txt
// iptables-restore < file.txt
// port ranges? iptables -A INPUT -p tcp -m tcp -m multiport --dports 1:79,81:442,444:65535 -j DROP
// list rules with line numbers: iptables -L --line-numbers
// modify rule at line number: iptables -R INPUT 12 -s 5.158.0.0/16 -j DROP
