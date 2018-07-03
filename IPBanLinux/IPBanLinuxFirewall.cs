using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace IPBan
{
    public class IPBanLinuxFirewall : IIPBanFirewall
    {
        private HashSet<string> bannedIPAddresses;

        private void LoadIPAddressesFromIPSet(string ruleName, string tempFile)
        {
            if (bannedIPAddresses == null)
            {
                bannedIPAddresses = new HashSet<string>();
                Process.Start("ipset", "create \"" + ruleName + "\" iphash maxelem 1048576").WaitForExit();
                Process.Start("ipset", "save \"" + ruleName + "\" > \"" + tempFile + "\"").WaitForExit();
                foreach (string line in File.ReadLines(tempFile).Skip(1))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 2 && IPAddress.TryParse(pieces[2], out _))
                    {
                        bannedIPAddresses.Add(pieces[2]);
                    }
                }
            }
        }

        public string RulePrefix { get; set; } = "IPBan_BlockIPAddresses_0";

        public bool CreateRules(IReadOnlyList<string> ipAddresses)
        {
            // ensure an ip set is created
            string ruleName = RulePrefix + "_0";
            string tempFile = Path.GetTempFileName();
            HashSet<string> newBannedIPAddresses = new HashSet<string>(ipAddresses);
            LoadIPAddressesFromIPSet(ruleName, tempFile);
            IEnumerable<string> removedIPAddresses = newBannedIPAddresses.Except(bannedIPAddresses);

            // add and remove the appropriate ip addresses
            StringBuilder script = new StringBuilder();
            foreach (string ipAddress in removedIPAddresses)
            {
                script.AppendLine("del \"" + ruleName + "\" \"" + ipAddress + "\" -exist");
            }
            foreach (string ipAddress in newBannedIPAddresses)
            {
                script.AppendLine("add \"" + ruleName + "\" \"" + ipAddress + "\" -exist");
            }

            // write out the file and run the command to restore the set
            bannedIPAddresses = newBannedIPAddresses;
            File.WriteAllText(tempFile, script.ToString());
            Process p = Process.Start("ipset", "restore \"" + ruleName + "\" < \"" + tempFile + "\"");
            return (p.ExitCode == 0);
        }

        public bool DeleteRules(int startIndex = 0)
        {
            // never delete rules, this is all handled in CreateRules
            return false;
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return bannedIPAddresses;
        }

        public bool IsIPAddressBlocked(string ipAddress)
        {
            return bannedIPAddresses.Contains(ipAddress);
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