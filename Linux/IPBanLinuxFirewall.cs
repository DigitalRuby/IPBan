using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    [RequiredOperatingSystem(IPBanOS.Linux)]
    public class IPBanLinuxFirewall : IIPBanFirewall
    {
        private const string inetFamily = "inet"; // inet6 when ipv6 support added

        private HashSet<string> bannedIPAddresses;
        private HashSet<string> allowedIPAddresses;
        private string allowRulePrefix;
        private string blockRulePrefix;

        private int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            commandLine = program + " " + string.Format(commandLine, args);
            commandLine = "-c \"" + commandLine.Replace("\"", "\\\"") + "\"";
            IPBanLog.Debug("Running firewall process: /bin/bash {0}", commandLine);
            Process p = Process.Start("/bin/bash", commandLine);
            p.WaitForExit();
            if (requireExitCode && p.ExitCode != 0)
            {
                IPBanLog.Error("Process {0} {1} had exit code {2}", program, commandLine, p.ExitCode);
            }
            return p.ExitCode;
        }

        private void LoadIPAddresses(string ruleName, string action, string tempFile, ref HashSet<string> ipAddresses)
        {
            if (ipAddresses == null)
            {
                ipAddresses = new HashSet<string>();
                RunProcess("ipset", false, $"create {ruleName} iphash family {inetFamily} hashsize 1024 maxelem 1048576 -exist");
                if (RunProcess("iptables", false, $"-C INPUT -m set --match-set \"{ruleName}\" src -j {action}") != 0)
                {
                    RunProcess("iptables", true, $"-A INPUT -m set --match-set \"{ruleName}\" src -j {action}");
                }
                RunProcess("ipset", true, "save {0} > \"{1}\"", ruleName, tempFile);
                foreach (string line in File.ReadLines(tempFile).Skip(1))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 2 && IPAddress.TryParse(pieces[2], out _))
                    {
                        ipAddresses.Add(pieces[2]);
                    }
                }
            }
        }

        private void DeleteFile(string fileName)
        {
            try
            {
                File.Delete(fileName);
            }
            catch
            {
            }
        }

        private bool UpdateRule(string ruleName, IEnumerable<string> ipAddresses, ref HashSet<string> existingIPAddresses, params PortRange[] allowPorts)
        {
            // ensure an ip set is created
            string tempFile = Path.GetTempFileName();
            HashSet<string> newIPAddresses = new HashSet<string>(ipAddresses);
            IEnumerable<string> removedIPAddresses = existingIPAddresses.Except(newIPAddresses);

            // add and remove the appropriate ip addresses
            StringBuilder script = new StringBuilder();
            script.AppendLine($"create {ruleName} hash:ip family {inetFamily} hashsize 1024 maxelem 1048576 -exist");
            foreach (string ipAddress in removedIPAddresses)
            {
                script.AppendLine($"del {ruleName} {ipAddress} -exist");
            }
            foreach (string ipAddress in newIPAddresses)
            {
                if (ipAddress.TryGetFirewallIPAddress(out string firewallIPAddress))
                {
                    script.AppendLine($"add {ruleName} {firewallIPAddress} -exist");
                }
            }

            // write out the file and run the command to restore the set
            existingIPAddresses = newIPAddresses;
            File.WriteAllText(tempFile, script.ToString());
            bool result = (RunProcess("ipset", true, $"restore < \"{tempFile}\"") == 0);
            DeleteFile(tempFile);
            return result;
        }

        public string RulePrefix { get; private set; } = "IPBan_";

        public void Initialize(string rulePrefix)
        {
            if (string.IsNullOrWhiteSpace(rulePrefix))
            {
                rulePrefix = "IPBan_";
            }
            RulePrefix = rulePrefix.Trim();
            allowRulePrefix = RulePrefix + "1";
            blockRulePrefix = RulePrefix + "0";
            string tempFile = Path.GetTempFileName();
            LoadIPAddresses(allowRulePrefix, "ACCEPT", tempFile, ref allowedIPAddresses);
            LoadIPAddresses(blockRulePrefix, "DROP", tempFile, ref bannedIPAddresses);
            DeleteFile(tempFile);
        }

        public bool BlockIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            return UpdateRule(blockRulePrefix, ipAddresses, ref bannedIPAddresses);
        }

        public void BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, params PortRange[] allowedPorts)
        {
            throw new NotImplementedException();

            //HashSet<string> tmp = null;
            //string ruleName = blockRulePrefix + "_" + ruleNamePrefix;
            //RunProcess("ipset", false, $"create {ruleName} iphash family {inetFamily} hashsize 1024 maxelem 1048576 -exist");
            //UpdateRule(ruleName, ranges.Select(r => r.ToCidrString()), ref tmp);
        }

        public bool AllowIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            return UpdateRule(allowRulePrefix, ipAddresses, ref allowedIPAddresses);
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return bannedIPAddresses;
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return allowedIPAddresses;
        }

        public bool IsIPAddressBlocked(string ipAddress)
        {
            return bannedIPAddresses.Contains(ipAddress);
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            return allowedIPAddresses.Contains(ipAddress);
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
// port ranges? iptables -A INPUT -p tcp -m tcp -m multiport ! --dports 80,443 -j DROP