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
    /// <summary>
    /// Linux Firewall for IPV6, is wrapped inside IPBanLinuxFirewall
    /// </summary>
    internal class IPBanLinuxFirewall6 : IPBanBaseFirewall, IIPBanFirewall
    {
        private const string inetFamily = "inet6";
        private const int hashSize = 1024;
        private const int blockRuleMaxCount = 2097152;
        private const int allowRuleMaxCount = 16384;
        private const int blockRuleRangesMaxCount = 4194304;

        private List<UInt128> bannedIPAddresses;
        private List<UInt128> allowedIPAddresses;
        private string allowRuleName;
        private string blockRuleName;

        private string GetSetFileName(string ruleName)
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ruleName + ".set6");
        }

        private string GetTableFileName()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ipban.tbl6");
        }

        private int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            return RunProcess(program, requireExitCode, out _, commandLine, args);
        }

        private int RunProcess(string program, bool requireExitCode, out IReadOnlyList<string> lines, string commandLine, params object[] args)
        {
            commandLine = string.Format(commandLine, args);
            string bash = "-c \"" + program + " " + commandLine.Replace("\"", "\\\"") + "\"";
            IPBanLog.Debug("Running firewall process: {0} {1}", program, commandLine);
            using (Process p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = bash,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                }
            })
            {
                p.Start();
                List<string> lineList = new List<string>();
                string line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    lineList.Add(line);
                }
                lines = lineList;
                if (!p.WaitForExit(60000))
                {
                    IPBanLog.Error("Process {0} {1} timed out", program, commandLine);
                    p.Kill();
                }
                if (requireExitCode && p.ExitCode != 0)
                {
                    IPBanLog.Error("Process {0} {1} had exit code {2}", program, commandLine, p.ExitCode);
                }
                return p.ExitCode;
            }
        }

        private void DeleteSet(string ruleName)
        {
            RunProcess("ipset", true, out IReadOnlyList<string> lines, "list -n");
            foreach (string line in lines)
            {
                if (line.Trim().Equals(ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    // remove set
                    RunProcess("ipset", true, $"destroy {ruleName}");
                    string setFileName = GetSetFileName(ruleName);
                    if (File.Exists(setFileName))
                    {
                        File.Delete(setFileName);
                    }
                    break;
                }
            }
        }

        private void SaveTableToDisk()
        {
            // persist table rules, this file is tiny so no need for a temp file and then move
            string tableFileName = GetTableFileName();
            RunProcess("ip6tables-save", true, $"> \"{tableFileName}\"");
        }

        private bool CreateOrUpdateRule(string ruleName, string action, string hashType, int maxCount, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken)
        {
            // ensure that a set exists for the ip6tables rule in the event that this is the first run
            RunProcess("ipset", true, $"create {ruleName} hash:{hashType} family {inetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

            string setFileName = GetSetFileName(ruleName);
            if (!File.Exists(setFileName))
            {
                RunProcess("ipset", true, $"save {ruleName} > \"{setFileName}\"");
            }

            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

            PortRange[] allowedPortsArray = allowedPorts?.ToArray();

            // create or update the rule in ip6tables
            RunProcess("ip6tables", true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string portString = " ";
            bool replaced = false;
            if (allowedPortsArray != null && allowedPortsArray.Length != 0)
            {
                string portList = (action == "DROP" ? IPBanFirewallUtility.GetPortRangeStringBlockExcept(allowedPorts) :
                     IPBanFirewallUtility.GetPortRangeStringAllow(allowedPorts));
                portString = " -m multiport --dports " + portList.Replace('-', ':') + " "; // ip6tables uses ':' instead of '-' for range
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
                    RunProcess("ip6tables", true, $"-R INPUT {ruleNum} -m set{portString}--match-set \"{ruleName}\" src -j {action}");
                    replaced = true;
                    break;
                }
            }
            if (!replaced)
            {
                // add a new rule
                RunProcess("ip6tables", true, $"-A INPUT -m set{portString}--match-set \"{ruleName}\" src -j {action}");
            }

            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

            SaveTableToDisk();

            return true;
        }

        private List<UInt128> LoadIPAddresses(string ruleName, string action, string hashType, int maxCount)
        {
            List<UInt128> ipAddresses = new List<UInt128>();

            try
            {
                if (hashType != "ip")
                {
                    throw new ArgumentException("Can only load hash of type 'ip'");
                }

                CreateOrUpdateRule(ruleName, action, hashType, maxCount, null, default);

                // copy ip addresses from the rule to the set
                string fileName = GetSetFileName(ruleName);
                if (File.Exists(fileName))
                {
                    UInt128 value;
                    foreach (string line in File.ReadLines(fileName).Skip(1))
                    {
                        string[] pieces = line.Split(' ');
                        if (pieces.Length > 2 && pieces[0] == "add" && (value = IPBanFirewallUtility.ParseIPV6(pieces[2])) != 0)
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
        private List<UInt128> UpdateRule(string ruleName, string action, IEnumerable<string> ipAddresses,
            List<UInt128> existingIPAddresses, string hashType, int maxCount, bool deleteRule, IEnumerable<PortRange> allowPorts, CancellationToken cancelToken,
            out bool result)
        {
            string ipFile = GetSetFileName(ruleName);
            string ipFileTemp = ipFile + ".tmp";
            List<UInt128> newIPAddressesUint = new List<UInt128>();
            UInt128 value = 0;

            // add and remove the appropriate ip addresses from the set
            using (StreamWriter writer = File.CreateText(ipFileTemp))
            {
                if (cancelToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancelToken);
                }
                writer.WriteLine($"create {ruleName} hash:{hashType} family {inetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
                foreach (string ipAddress in ipAddresses)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancelToken);
                    }

                    value = 0;
                    if (IPAddressRange.TryParse(ipAddress, out IPAddressRange range) &&
                        range.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                        range.End.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                        // if deleting the rule, don't track the UInt128 value
                        (!deleteRule || (value = IPBanFirewallUtility.ParseIPV6(ipAddress)) != 0))
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
                                newIPAddressesUint.Add((value == 0 ? IPBanFirewallUtility.ParseIPV6(ipAddress) : value));
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
                    foreach (UInt128 droppedIP in existingIPAddresses.Where(e => newIPAddressesUint.BinarySearch(e) < 0))
                    {
                        writer.WriteLine($"del {ruleName} {IPBanFirewallUtility.IPV6ToString(droppedIP)} -exist");
                    }
                }
            }

            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }
            else
            {
                // TODO: Is there an easier way to move to a file that exists?
                if (File.Exists(ipFile))
                {
                    DeleteFile(ipFile);
                }
                File.Move(ipFileTemp, ipFile);

                if (deleteRule)
                {
                    DeleteRule(ruleName);
                }

                // restore the file to get the set updated
                result = (RunProcess("ipset", true, $"restore < \"{ipFile}\"") == 0);

                // ensure rule exists for the set
                CreateOrUpdateRule(ruleName, action, hashType, maxCount, allowPorts, cancelToken);
            }

            return newIPAddressesUint;
        }

        public IPBanLinuxFirewall6(string rulePrefix = null) : base(rulePrefix)
        {
            allowRuleName = RulePrefix + "1";
            blockRuleName = RulePrefix + "0";

            /*
            // restore existing sets from disk
            RunProcess("ipset", true, out IReadOnlyList<string> existingSets, $"-L | grep ^Name:");
            foreach (string set in existingSets.Where(s => s.StartsWith("Name: " + RulePrefix, StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Substring("Name: ".Length)))
            {
                RunProcess("ipset", true, $"flush {set}");
            }
            */

            foreach (string setFile in Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.set6"))
            {
                RunProcess("ipset", true, $"restore < \"{setFile}\"");
            }

            allowedIPAddresses = LoadIPAddresses(allowRuleName, "ACCEPT", "ip", allowRuleMaxCount);
            bannedIPAddresses = LoadIPAddresses(blockRuleName, "DROP", "ip", blockRuleMaxCount);

            // restore existing rules from disk
            string ruleFile = GetTableFileName();
            if (File.Exists(ruleFile))
            {
                RunProcess("ip6tables-restore", true, $"< \"{ruleFile}\"");
            }
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ruleNamePrefix))
                {
                    ruleNamePrefix = blockRuleName;
                }
                else
                {
                    ruleNamePrefix = RulePrefix + ruleNamePrefix;
                }
                bannedIPAddresses = UpdateRule(ruleNamePrefix, "DROP", ipAddresses, bannedIPAddresses, "ip", blockRuleMaxCount, false, null, cancelToken, out bool result);
                return Task.FromResult(result);
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult(false);
            }
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            if (string.IsNullOrWhiteSpace(ruleNamePrefix))
            {
                return Task.FromResult(false);
            }

            try
            {
                string ruleName = RulePrefix + "_" + ruleNamePrefix + "_0";
                UpdateRule(ruleName, "DROP", ranges.Select(r => r.ToCidrString()), null, "net", blockRuleRangesMaxCount, true, allowedPorts, cancelToken, out bool result);
                return Task.FromResult(result);
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult(false);
            }
        }

        public Task UnblockIPAddresses(IEnumerable<string> ipAddresses)
        {
            bool changed = false;
            foreach (string ipAddress in ipAddresses)
            {
                if (IPAddress.TryParse(ipAddress, out IPAddress ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    UInt128 ipValue = ip.ToUInt128();
                    if (ipValue != 0 && !string.IsNullOrWhiteSpace(ipAddress) && RunProcess("ipset", true, $"del {blockRuleName} {ip} -exist") == 0)
                    {
                        bannedIPAddresses.Remove(ipValue);
                        changed = true;
                    }
                }
            }
            if (changed)
            {
                RunProcess("ipset", true, $"save {blockRuleName} > \"{GetSetFileName(blockRuleName)}\"");
            }
            return Task.CompletedTask;
        }

        public Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            try
            {
                allowedIPAddresses = UpdateRule(allowRuleName, "ACCEPT", ipAddresses, allowedIPAddresses, "ip", allowRuleMaxCount, false, null, cancelToken, out bool result);
                return Task.FromResult<bool>(result);
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult<bool>(false);
            }
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            const string setText = " match-set ";
            string prefix = setText + RulePrefix + (ruleNamePrefix ?? string.Empty);
            RunProcess("ip6tables", true, out IReadOnlyList<string> lines, "-L");
            foreach (string line in lines)
            {
                int pos = line.IndexOf(prefix);
                if (pos >= 0)
                {
                    pos += setText.Length;
                    int start = pos;
                    while (++pos < line.Length && line[pos] != ' ') { }
                    yield return line.Substring(start, pos - start);
                }
            }
        }

        public bool RuleExists(string ruleName)
        {
            RunProcess("ip6tables", true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string ruleNameWithSpaces = " " + ruleName + " ";
            foreach (string line in lines)
            {
                if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        public bool DeleteRule(string ruleName)
        {
            RunProcess("ip6tables", true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string ruleNameWithSpaces = " " + ruleName + " ";
            foreach (string line in lines)
            {
                if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                {
                    // rule number is first piece of the line
                    int index = line.IndexOf(' ');
                    int ruleNum = int.Parse(line.Substring(0, index));

                    // remove the rule from ip6tables
                    RunProcess("ip6tables", true, $"-D INPUT {ruleNum}");
                    SaveTableToDisk();

                    // remove the set
                    DeleteSet(ruleName);

                    return true;
                }
            }
            return false;
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return bannedIPAddresses.Select(b => IPBanFirewallUtility.IPV6ToString(b));
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return allowedIPAddresses.Select(b => IPBanFirewallUtility.IPV6ToString(b));
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            string prefix = RulePrefix + (ruleNamePrefix ?? string.Empty);
            string[] pieces;

            foreach (string setFile in Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.set6"))
            {
                if (Path.GetFileName(setFile).StartsWith(prefix))
                {
                    foreach (string line in File.ReadLines(setFile).Skip(1).Where(l => l.StartsWith("add ")))
                    {
                        // example line: add setname ipaddress -exist
                        pieces = line.Split(' ');
                        if (IPAddressRange.TryParse(pieces[2], out IPAddressRange range))
                        {
                            yield return range;
                        }
                    }
                }
            }
        }

        public bool IsIPAddressBlocked(string ipAddress, int port = -1)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return bannedIPAddresses.Contains(ip.ToUInt128());
            }
            return false;
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return allowedIPAddresses.Contains(ip.ToUInt128());
            }
            return false;
        }
    }
}
