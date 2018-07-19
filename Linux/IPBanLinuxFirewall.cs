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
    [RequiredOperatingSystem(IPBanOperatingSystem.Linux)]
    public class IPBanLinuxFirewall : IIPBanFirewall
    {
        private HashSet<string> bannedIPAddresses;
        private HashSet<string> allowedIPAddresses;

        private int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            commandLine = program + " " + string.Format(commandLine, args);
            commandLine = "-c \"" + commandLine.Replace("\"", "\\\"") + "\"";
            Log.Write(NLog.LogLevel.Debug, "Running firewall process: /bin/bash {0}", commandLine);
            Process p = Process.Start("/bin/bash", commandLine);
            p.WaitForExit();
            if (requireExitCode && p.ExitCode != 0)
            {
                Log.Write(NLog.LogLevel.Error, "Process {0} {1} had exit code {2}", program, commandLine, p.ExitCode);
            }
            return p.ExitCode;
        }

        private void LoadIPAddresses(string ruleName, string action, string tempFile, ref HashSet<string> ipAddresses)
        {
            if (ipAddresses == null)
            {
                ipAddresses = new HashSet<string>();
                RunProcess("ipset", false, "create {0} iphash maxelem 1048576", ruleName);
                // iptables -A INPUT -m set --set myset src -j DROP
                int result = RunProcess("iptables", false, "-C INPUT -m set --match-set \"{0}\" src -j {1}", ruleName, action);
                if (result != 0)
                {
                    RunProcess("iptables", true, "-A INPUT -m set --match-set \"{0}\" src -j {1}", ruleName, action);
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

        private bool UpdateRule(IReadOnlyList<string> ipAddresses, ref HashSet<string> existingIPAddresses)
        {
            // ensure an ip set is created
            string ruleName = RulePrefix + (existingIPAddresses == bannedIPAddresses ? "0" : "AllowIPAddresses");
            string tempFile = Path.GetTempFileName();
            HashSet<string> newIPAddresses = new HashSet<string>(ipAddresses);
            IEnumerable<string> removedIPAddresses = existingIPAddresses.Except(newIPAddresses);

            // add and remove the appropriate ip addresses
            StringBuilder script = new StringBuilder();
            script.AppendLine("create " + ruleName + " hash:ip family inet hashsize 1024 maxelem 1048576 -exist");
            foreach (string ipAddress in removedIPAddresses)
            {
                script.AppendLine("del " + ruleName + " " + ipAddress + " -exist");
            }
            foreach (string ipAddress in newIPAddresses)
            {
                if (ipAddress.TryGetFirewallIPAddress(out string firewallIPAddress))
                {
                    script.AppendLine("add " + ruleName + " " + firewallIPAddress + " -exist");
                }
            }

            // write out the file and run the command to restore the set
            existingIPAddresses = newIPAddresses;
            File.WriteAllText(tempFile, script.ToString());
            bool result = (RunProcess("ipset", true, "restore < \"{0}\"", tempFile) == 0);
            DeleteFile(tempFile);
            return result;
        }

        public string RulePrefix { get; private set; } = "IPBan_BlockIPAddresses_";

        public void Initialize(string rulePrefix)
        {
            RulePrefix = rulePrefix;
            string tempFile = Path.GetTempFileName();
            LoadIPAddresses(RulePrefix + "0", "DROP", tempFile, ref bannedIPAddresses);
            LoadIPAddresses(RulePrefix + "AllowIPAddresses", "ACCEPT", tempFile, ref allowedIPAddresses);
            DeleteFile(tempFile);
        }

        public bool BlockIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            return UpdateRule(ipAddresses, ref bannedIPAddresses);
        }

        public bool AllowIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            return UpdateRule(ipAddresses, ref allowedIPAddresses);
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