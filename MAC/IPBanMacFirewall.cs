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

namespace IPBan
{
    // TODO: use pfctl
    [RequiredOperatingSystem(IPBanOS.Mac)]
    public class IPBanMacFirewall : IIPBanFirewall
    {
        public string RulePrefix { get; private set; }

        public void Initialize(string rulePrefix)
        {
            if (string.IsNullOrWhiteSpace(rulePrefix))
            {
                rulePrefix = "IPBan_";
            }
            RulePrefix = rulePrefix.Trim();
        }

        public bool AllowIPAddresses(IEnumerable<string> ipAddresses)
        {
            throw new NotImplementedException();
        }

        public Task<bool> BlockIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            throw new NotImplementedException();
        }

        public bool RuleExists(string ruleName)
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

        public bool IsIPAddressBlocked(string ipAddress)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
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