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
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    // TODO: use pfctl
    [RequiredOperatingSystem(IPBanOS.Mac)]
    [CustomName("Default")]
    public class IPBanMacFirewall : IPBanBaseFirewall, IIPBanFirewall
    {
        public IPBanMacFirewall(string rulePrefix = null) : base(rulePrefix)
        {
        }

        public Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            throw new NotImplementedException();
        }

        public bool DeleteRule(string ruleName)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            throw new NotImplementedException();
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            throw new NotImplementedException();
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            throw new NotImplementedException();
        }

        public bool IsIPAddressBlocked(string ipAddress, int port = -1)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            throw new NotImplementedException();
        }

        public void Truncate()
        {
            throw new NotImplementedException();
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