using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace IPBan
{
    [RequiredOperatingSystem(IPBanOS.Linux)]
    public class IPBanLinuxFirewall : IIPBanFirewall
    {
        private const string inetFamily = "inet"; // inet6 when ipv6 support added
        private const int hashSize = 1024;
        private const int blockRuleMaxCount = 2097152;
        private const int allowRuleMaxCount = 65536;
        private const int blockRuleRangesMaxCount = 4194304;

        private List<uint> bannedIPAddresses;
        private List<uint> allowedIPAddresses;
        private string allowRuleName;
        private string blockRuleName;

        private string GetSetFileName(string ruleName)
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ruleName + ".set");
        }

        private string GetTableFileName()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ipban.tbl");
        }

        private int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            commandLine = program + " " + string.Format(commandLine, args);
            commandLine = "-c \"" + commandLine.Replace("\"", "\\\"") + "\"";
            IPBanLog.Debug("Running firewall process: /bin/bash {0}", commandLine);
            Process p = Process.Start("/bin/bash", commandLine);
            p.WaitForExit();
            if (requireExitCode && p.ExitCode != 0)
            {
                IPBanLog.Error("Process {0} had exit code {1}", commandLine, p.ExitCode);
            }
            return p.ExitCode;
        }

        private void DeleteRule(string ruleName)
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                RunProcess("iptables", true, "-L --line-numbers > \"{0}\"", tempFile);
                string[] lines = File.ReadAllLines(tempFile);
                string ruleNameWithSpaces = " " + ruleName + " ";
                foreach (string line in lines)
                {
                    if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                    {
                        // rule number is first piece of the line
                        int index = line.IndexOf(' ');
                        int ruleNum = int.Parse(line.Substring(0, index));

                        // replace the rule with the new info
                        RunProcess("iptables", true, $"-D INPUT {ruleNum}");
                        break;
                    }
                }
            }
            finally
            {
                DeleteFile(tempFile);
            }
        }

        private void DeleteSet(string ruleName)
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                RunProcess("ipset", true, "list -n > \"{0}\"", tempFile);
                foreach (string line in File.ReadAllLines(tempFile))
                {
                    if (line.Trim().Equals(ruleName, StringComparison.OrdinalIgnoreCase))
                    {
                        RunProcess("ipset", true, $"destroy {ruleName}");
                        break;
                    }
                }
            }
            finally
            {
                DeleteFile(tempFile);
            }
        }

        private void CreateOrUpdateRule(string ruleName, string action, string hashType, int maxCount, params PortRange[] allowedPorts)
        {
            // ensure that a set exists for the iptables rule in the event that this is the first run
            RunProcess("ipset", false, $"create {ruleName} hash:{hashType} family {inetFamily} hashsize {hashSize} maxelem {maxCount} -exist");

            string setFileName = GetSetFileName(ruleName);
            if (!File.Exists(setFileName))
            {
                RunProcess("ipset", true, $"save {ruleName} > \"{setFileName}\"");
            }

            // create or update the rule in iptables
            string tempFile = Path.GetTempFileName();
            try
            {
                RunProcess("iptables", true, "-L --line-numbers > \"{0}\"", tempFile);
                string[] lines = File.ReadAllLines(tempFile);
                string portString = " ";
                bool replaced = false;
                if (allowedPorts.Length != 0)
                {
                    string portList = (action == "DROP" ? IPBanFirewallUtility.GetPortRangeStringBlockExcept(allowedPorts) :
                         IPBanFirewallUtility.GetPortRangeStringAllow(allowedPorts));
                    portString = " -m multiport --dports " + portList.Replace('-', ':') + " "; // iptables uses ':' instead of '-' for range
                }
                string ruleNameWithSpaces = " " + ruleName + " ";
                foreach (string line in lines)
                {
                    if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                    {
                        // rule number is first piece of the line
                        int index = line.IndexOf(' ');
                        int ruleNum = int.Parse(line.Substring(0, index));

                        // replace the rule with the new info
                        RunProcess("iptables", true, $"-R INPUT {ruleNum} -m set{portString}--match-set \"{ruleName}\" src -j {action}");
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                {
                    // add a new rule
                    RunProcess("iptables", true, $"-A INPUT -m set{portString}--match-set \"{ruleName}\" src -j {action}");
                }

                // persist table rules, this file is tiny so no need for a temp file and then move
                RunProcess("iptables-save", true, $"> \"{GetTableFileName()}\"");
            }
            finally
            {
                DeleteFile(tempFile);
            }
        }

        private List<uint> LoadIPAddresses(string ruleName, string action, string hashType, int maxCount)
        {
            List<uint> ipAddresses = new List<uint>();

            try
            {
                if (hashType != "ip")
                {
                    throw new ArgumentException("Can only load hash of type 'ip'");
                }

                CreateOrUpdateRule(ruleName, action, hashType, maxCount);

                // copy ip addresses from the rule to the set
                string fileName = GetSetFileName(ruleName);
                if (File.Exists(fileName))
                {
                    uint value;
                    foreach (string line in File.ReadLines(fileName).Skip(1))
                    {
                        string[] pieces = line.Split(' ');
                        if (pieces.Length > 2 && pieces[0] == "add" && (value = IPBanFirewallUtility.ParseIPV4(pieces[2])) != 0)
                        {
                            ipAddresses.Add(value);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }

            return ipAddresses;
        }

        private void DeleteFile(string fileName)
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    File.Delete(fileName);
                    break;
                }
                catch
                {
                    Task.Delay(20).Wait();
                }
            }
        }

        // deleteRule will drop the rule and matching set before creating the rule and set, use this is you don't care to update the rule and set in place
        private List<uint> UpdateRule(string ruleName, string action, IEnumerable<string> ipAddresses,
            List<uint> existingIPAddresses, string hashType, int maxCount, bool deleteRule, out bool result, params PortRange[] allowPorts)
        {
            string ipFile = GetSetFileName(ruleName);
            string ipFileTemp = ipFile + ".tmp";
            List<uint> newIPAddressesUint = new List<uint>();
            uint value = 0;

            // add and remove the appropriate ip addresses from the set
            using (StreamWriter writer = File.CreateText(ipFileTemp))
            {
                writer.WriteLine($"create {ruleName} hash:{hashType} family {inetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
                foreach (string ipAddress in ipAddresses)
                {
                    // only allow ipv4 for now
                    if (IPAddressRange.TryParse(ipAddress, out IPAddressRange range) &&
                        range.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                        range.End.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                        // if deleting the rule, don't track the uint value
                        (!deleteRule || (value = IPBanFirewallUtility.ParseIPV4(ipAddress)) != 0))
                    {
                        try
                        {
                            if (range.Begin.Equals(range.End))
                            {
                                writer.WriteLine($"add {ruleName} {range.Begin} -exist");
                            }
                            else
                            {
                                writer.WriteLine($"add {ruleName} {range.ToCidrString()} -exist");
                            }
                            if (!deleteRule)
                            {
                                newIPAddressesUint.Add(value);
                            }
                        }
                        catch
                        {
                            // ignore invalid cidr ranges
                        }
                    }
                }
                newIPAddressesUint.Sort();

                // if the rule was deleted, no need to add del entries
                if (!deleteRule)
                {
                    // for ip that dropped out, remove from firewall
                    foreach (uint droppedIP in existingIPAddresses.Where(e => newIPAddressesUint.BinarySearch(e) < 0))
                    {
                        writer.WriteLine($"del {ruleName} {IPBanFirewallUtility.IPV4ToString(droppedIP)} -exist");
                    }
                }
            }

            // TODO: Is there a way to move to a file that exists?
            if (File.Exists(ipFile))
            {
                DeleteFile(ipFile);
            }
            File.Move(ipFileTemp, ipFile);

            if (deleteRule)
            {
                DeleteRule(ruleName);
                DeleteSet(ruleName);
            }

            // restore the file to get the set updated
            result = (RunProcess("ipset", true, $"restore < \"{ipFile}\"") == 0);

            // ensure rule exists for the set
            CreateOrUpdateRule(ruleName, action, hashType, maxCount, allowPorts);

            return newIPAddressesUint;
        }

        public string RulePrefix { get; private set; } = "IPBan_";

        public void Initialize(string rulePrefix)
        {
            if (string.IsNullOrWhiteSpace(rulePrefix))
            {
                rulePrefix = "IPBan_";
            }          
            
            RulePrefix = rulePrefix.Trim();
            allowRuleName = RulePrefix + "1";
            blockRuleName = RulePrefix + "0";

            // restore existing sets from disk
            foreach (string setFile in Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.set"))
            {
                RunProcess("ipset", true, $"restore < \"{setFile}\"");
            }

            allowedIPAddresses = LoadIPAddresses(allowRuleName, "ACCEPT", "ip", allowRuleMaxCount);
            bannedIPAddresses = LoadIPAddresses(blockRuleName, "DROP", "ip", blockRuleMaxCount);

            // restore existing rules from disk
            string ruleFile = GetTableFileName();
            if (File.Exists(ruleFile))
            {
                RunProcess("iptables-restore", true, $"< \"{ruleFile}\"");
            }
        }

        public bool BlockIPAddresses(IEnumerable<string> ipAddresses)
        {
            try
            {
                bannedIPAddresses = UpdateRule(blockRuleName, "DROP", ipAddresses, bannedIPAddresses, "ip", blockRuleMaxCount, false, out bool result);
                return result;
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return false;
            }
        }

        public bool BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, params PortRange[] allowedPorts)
        {
            try
            {
                string ruleName = blockRuleName + "_" + ruleNamePrefix;
                UpdateRule(ruleName, "DROP", ranges.Select(r => r.ToCidrString()), null, "net", blockRuleRangesMaxCount, true, out bool result, allowedPorts);
                return result;
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return false;
            }
        }

        public bool AllowIPAddresses(IEnumerable<string> ipAddresses)
        {
            try
            {
                allowedIPAddresses = UpdateRule(allowRuleName, "ACCEPT", ipAddresses, allowedIPAddresses, "ip", allowRuleMaxCount, false, out bool result);
                return result;
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return false;
            }
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return bannedIPAddresses.Select(b => IPBanFirewallUtility.IPV4ToString(b));
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return allowedIPAddresses.Select(b => IPBanFirewallUtility.IPV4ToString(b));
        }

        public bool IsIPAddressBlocked(string ipAddress)
        {
            return bannedIPAddresses.Contains(IPBanFirewallUtility.ParseIPV4(ipAddress));
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            return allowedIPAddresses.Contains(IPBanFirewallUtility.ParseIPV4(ipAddress));
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
