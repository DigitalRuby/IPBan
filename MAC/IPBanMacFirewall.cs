using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    // TODO: use pfctl
    [RequiredOperatingSystem(IPBanOS.Mac)]
    public class IPBanMacFirewall : IIPBanFirewall
    {
        public bool AllowIPAddresses(IEnumerable<string> ipAddresses)
        {
            throw new NotImplementedException();
        }

        public bool BlockIPAddresses(IEnumerable<string> ipAddresses)
        {
            throw new NotImplementedException();
        }

        public bool BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, params PortRange[] allowedPorts)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
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

        public void Initialize(string rulePrefix)
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