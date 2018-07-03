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

        private bool RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            commandLine = program + " " + string.Format(commandLine, args);
            commandLine = "-c \"" + commandLine.Replace("\"", "\\\"") + "\"";
            Log.Write(NLog.LogLevel.Debug, "Running firewall process: /bin/bash {0}", commandLine);
            Process p = Process.Start("/bin/bash", commandLine);
            p.WaitForExit();
            if (requireExitCode && p.ExitCode != 0)
            {
                Log.Write(NLog.LogLevel.Error, "Process {0} {1} had exit code {2}", program, commandLine, p.ExitCode);
                return false;
            }
            return true;
        }

        private void LoadIPAddressesFromIPSet(string ruleName, string tempFile)
        {
            if (bannedIPAddresses == null)
            {
                bannedIPAddresses = new HashSet<string>();
                RunProcess("ipset", false, "create {0} iphash maxelem 1048576", ruleName);
                RunProcess("iptables", false, "-A INPUT -m set --match-set \"{0}\" dst -j DROP", ruleName);
                RunProcess("ipset", true, "save {0} > \"{1}\"", ruleName, tempFile);
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

        public string RulePrefix { get; set; } = "IPBan_BlockIPAddresses_";

        public bool CreateRules(IReadOnlyList<string> ipAddresses)
        {
            // ensure an ip set is created
            string ruleName = RulePrefix + "0";
            string tempFile = Path.GetTempFileName();
            HashSet<string> newBannedIPAddresses = new HashSet<string>(ipAddresses);
            LoadIPAddressesFromIPSet(ruleName, tempFile);
            IEnumerable<string> removedIPAddresses = bannedIPAddresses.Except(newBannedIPAddresses);

            // add and remove the appropriate ip addresses
            StringBuilder script = new StringBuilder();
            script.AppendLine("create " + ruleName + " hash:ip family inet hashsize 1024 maxelem 1048576 -exist");
            foreach (string ipAddress in removedIPAddresses)
            {
                script.AppendLine("del " + ruleName + " " + ipAddress + " -exist");
            }
            foreach (string ipAddress in newBannedIPAddresses)
            {
                script.AppendLine("add " + ruleName + " " + ipAddress + " -exist");
            }

            // write out the file and run the command to restore the set
            bannedIPAddresses = newBannedIPAddresses;
            File.WriteAllText(tempFile, script.ToString());
            return RunProcess("ipset", true, "restore < \"{0}\"", tempFile);
        }

        public bool DeleteRules(int startIndex = 0)
        {
            // never delete rules, this is all handled in CreateRules
            return false;
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return ((IEnumerable<string>)bannedIPAddresses ?? new string[0]);
        }

        public bool IsIPAddressBlocked(string ipAddress)
        {
            return (bannedIPAddresses == null ? false : bannedIPAddresses.Contains(ipAddress));
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