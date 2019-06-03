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
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    public abstract class IPBanLinuxBaseFirewall : IPBanBaseFirewall, IIPBanFirewall
    {
        private readonly AddressFamily addressFamily;
        private DateTime lastUpdate = IPBanService.UtcNow;

        protected const int hashSize = 1024;
        protected const int blockRuleMaxCount = 2097152;
        protected const int allowRuleMaxCount = 8192;
        protected const int blockRuleRangesMaxCount = 4194304;

        protected virtual bool IsIPV4 => true;
        protected virtual string INetFamily => "inet";
        protected virtual string SetSuffix => ".set";
        protected virtual string TableSuffix => ".tbl";
        protected virtual string IpTablesProcess => "iptables";

        private void RemoveAllTablesAndSets()
        {
            if (!IsIPV4)
            {
                return;
            }

            try
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                foreach (string setFile in Directory.GetFiles(dir, "*.set")
                    .Union(Directory.GetFiles(dir, "*.tbl")
                    .Union(Directory.GetFiles(dir, "*.set6"))
                    .Union(Directory.GetFiles(dir, "*.tbl6"))))
                {
                    File.Delete(setFile);
                }
                RunProcess(IpTablesProcess, true, "-F");
                RunProcess("ipset", true, "destroy");
            }
            catch
            {
            }
        }

        private void DeleteSet(string ruleName)
        {
            RunProcess("ipset", true, out IReadOnlyList<string> lines, "list -n");
            foreach (string line in lines)
            {
                if (line.Trim().Equals(ruleName, StringComparison.OrdinalIgnoreCase))
                {
                    RunProcess("ipset", true, $"destroy {ruleName}");
                    break;
                }
            }
        }

        private void SaveSetsToDisk()
        {
            // ipv6 is an inner wrapper, do not do this for ipv6
            if (IsIPV4)
            {
                string setFile = GetSetFileName();
                RunProcess("ipset", true, $"save > \"{setFile}\"");
            }
        }

        private void RestoreSetsFromDisk()
        {
            // ipv6 is an inner wrapper, do not do this for ipv6
            if (IsIPV4)
            {
                string setFile = GetSetFileName();
                if (File.Exists(setFile))
                {
                    RunProcess("ipset", true, $"restore < \"{setFile}\"");
                }
            }
        }

        private void SaveTableToDisk()
        {
            // persist table rules, this file is tiny so no need for a temp file and then move
            string tableFileName = GetTableFileName();
            RunProcess($"{IpTablesProcess}-save", true, $"> \"{tableFileName}\"");
        }

        private void RestoreTablesFromDisk()
        {
            string tableFileName = GetTableFileName();
            if (File.Exists(tableFileName))
            {
                RunProcess($"{IpTablesProcess}-restore", true, $"< \"{tableFileName}\"");
            }
        }

        protected string GetTableFileName()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ipban" + TableSuffix);
        }

        protected string GetSetFileName()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ipban.set");
        }

        protected int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            return RunProcess(program, requireExitCode, out _, commandLine, args);
        }

        protected int RunProcess(string program, bool requireExitCode, out IReadOnlyList<string> lines, string commandLine, params object[] args)
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

        protected bool CreateOrUpdateRule(string ruleName, string action, string hashType, int maxCount, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken)
        {
            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

            PortRange[] allowedPortsArray = allowedPorts?.ToArray();

            // create or update the rule in iptables
            RunProcess(IpTablesProcess, true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string portString = " ";
            bool replaced = false;
            if (allowedPortsArray != null && allowedPortsArray.Length != 0)
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
                    RunProcess(IpTablesProcess, true, $"-R INPUT {ruleNum} -m set{portString}--match-set \"{ruleName}\" src -j {action}");
                    replaced = true;
                    break;
                }
            }
            if (!replaced)
            {
                // add a new rule
                RunProcess(IpTablesProcess, true, $"-A INPUT -m set{portString}--match-set \"{ruleName}\" src -j {action}");
            }

            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

            SaveTableToDisk();

            return true;
        }

        // deleteRule will drop the rule and matching set before creating the rule and set, use this is you don't care to update the rule and set in place
        protected bool UpdateRule(string ruleName, string action, IEnumerable<string> ipAddresses, string hashType, int maxCount,
            IEnumerable<PortRange> allowPorts, CancellationToken cancelToken)
        {
            string ipFileTemp = Path.GetTempFileName();
            try
            {
                // add and remove the appropriate ip addresses from the set
                using (StreamWriter writer = File.CreateText(ipFileTemp))
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancelToken);
                    }
                    RunProcess("ipset", true, out IReadOnlyList<string> sets, "-L -n");
                    if (sets.Contains(ruleName))
                    {
                        writer.WriteLine($"flush {ruleName}");// hash:{hashType} family {INetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
                    }
                    writer.WriteLine($"create {ruleName} hash:{hashType} family {INetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
                    foreach (string ipAddress in ipAddresses)
                    {
                        if (cancelToken.IsCancellationRequested)
                        {
                            throw new OperationCanceledException(cancelToken);
                        }

                        if (IPAddressRange.TryParse(ipAddress, out IPAddressRange range) &&
                            range.Begin.AddressFamily == addressFamily && range.End.AddressFamily == addressFamily)
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
                            }
                            catch
                            {
                                // ignore invalid cidr ranges
                            }
                        }
                    }
                }

                if (cancelToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancelToken);
                }
                else
                {
                    // restore the set
                    bool result = (RunProcess("ipset", true, $"restore < \"{ipFileTemp}\"") == 0);
                    CreateOrUpdateRule(ruleName, action, hashType, maxCount, allowPorts, cancelToken);
                    return result;
                }
            }
            finally
            {
                File.Delete(ipFileTemp);
            }
        }

        // deleteRule will drop the rule and matching set before creating the rule and set, use this is you don't care to update the rule and set in place
        protected bool UpdateRuleDelta(string ruleName, string action, IEnumerable<IPBanFirewallIPAddressDelta> deltas, string hashType,
            int maxCount, bool deleteRule, IEnumerable<PortRange> allowPorts, CancellationToken cancelToken)
        {
            string ipFileTemp = Path.GetTempFileName();
            try
            {
                // add and remove the appropriate ip addresses from the set
                using (StreamWriter writer = File.CreateText(ipFileTemp))
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancelToken);
                    }
                    writer.WriteLine($"create {ruleName} hash:{hashType} family {INetFamily} hashsize {hashSize} maxelem {maxCount} -exist");
                    foreach (IPBanFirewallIPAddressDelta delta in deltas)
                    {
                        if (cancelToken.IsCancellationRequested)
                        {
                            throw new OperationCanceledException(cancelToken);
                        }

                        if (IPAddressRange.TryParse(delta.IPAddress, out IPAddressRange range) &&
                            range.Begin.AddressFamily == addressFamily && range.End.AddressFamily == addressFamily)
                        {
                            try
                            {
                                if (delta.Added)
                                {
                                    if (range.Begin.Equals(range.End))
                                    {
                                        writer.WriteLine($"add {ruleName} {range.Begin} -exist");
                                    }
                                    else
                                    {
                                        writer.WriteLine($"add {ruleName} {range.ToCidrString()} -exist");
                                    }
                                }
                                else
                                {
                                    if (range.Begin.Equals(range.End))
                                    {
                                        writer.WriteLine($"del {ruleName} {range.Begin} -exist");
                                    }
                                    else
                                    {
                                        writer.WriteLine($"del {ruleName} {range.ToCidrString()} -exist");
                                    }
                                }
                            }
                            catch
                            {
                                // ignore invalid cidr ranges
                            }
                        }
                    }
                }

                if (cancelToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancelToken);
                }
                else
                {
                    // restore the deltas into the existing set
                    bool result = (RunProcess("ipset", true, $"restore < \"{ipFileTemp}\"") == 0);
                    CreateOrUpdateRule(ruleName, action, hashType, maxCount, allowPorts, cancelToken);
                    return result;
                }
            }
            finally
            {
                File.Delete(ipFileTemp);
            }
        }

        protected override void OnDispose()
        {
            base.OnDispose();

            SaveSetsToDisk();
            SaveTableToDisk();
        }

        protected virtual void OnInitialize() { }

        public IPBanLinuxBaseFirewall(string rulePrefix = null) : base(rulePrefix)
        {
            /*
             // restore existing sets from disk
             RunProcess("ipset", true, out IReadOnlyList<string> existingSets, $"-L | grep ^Name:");
             foreach (string set in existingSets.Where(s => s.StartsWith("Name: " + RulePrefix, StringComparison.OrdinalIgnoreCase))
                 .Select(s => s.Substring("Name: ".Length)))
             {
                 RunProcess("ipset", true, $"flush {set}");
             }
            */

            addressFamily = (IsIPV4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6);
            OnInitialize();
            RestoreSetsFromDisk();
            RestoreTablesFromDisk();
        }

        public override void Update()
        {
            base.Update();

            // flush all sets to disk one per minute
            DateTime now = IPBanService.UtcNow;
            if ((now - lastUpdate) > TimeSpan.FromMinutes(1.0))
            {
                lastUpdate = now;
                SaveSetsToDisk();
            }
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            const string setText = " match-set ";
            string prefix = setText + RulePrefix + (ruleNamePrefix ?? string.Empty);
            RunProcess(IpTablesProcess, true, out IReadOnlyList<string> lines, "-L");
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

        public bool DeleteRule(string ruleName)
        {
            RunProcess(IpTablesProcess, true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string ruleNameWithSpaces = " " + ruleName + " ";
            foreach (string line in lines)
            {
                if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                {
                    // rule number is first piece of the line
                    int index = line.IndexOf(' ');
                    int ruleNum = int.Parse(line.Substring(0, index));

                    // remove the rule from iptables
                    RunProcess(IpTablesProcess, true, $"-D INPUT {ruleNum}");
                    SaveTableToDisk();

                    // remove the set
                    DeleteSet(ruleName);

                    return true;
                }
            }
            return false;
        }

        public virtual Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            try
            {
                string ruleName = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRuleName : RulePrefix + ruleNamePrefix);
                return Task.FromResult(UpdateRule(ruleName, "DROP", ipAddresses, "ip", blockRuleMaxCount, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult(false);
            }
        }

        public virtual Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> deltas, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            try
            {
                string ruleName = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRuleName : RulePrefix + ruleNamePrefix);
                return Task.FromResult(UpdateRuleDelta(ruleName, "DROP", deltas, "ip", blockRuleMaxCount, false, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult(false);
            }
        }

        public virtual Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            if (string.IsNullOrWhiteSpace(ruleNamePrefix))
            {
                return Task.FromResult(false);
            }

            try
            {
                string ruleName = RulePrefix + RuleSuffix + ruleNamePrefix;
                return Task.FromResult(UpdateRule(ruleName, "DROP", ranges.Select(r => r.ToCidrString()), "net", blockRuleRangesMaxCount, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult(false);
            }
        }

        public virtual Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            try
            {
                return Task.FromResult(UpdateRule(AllowRuleName, "ACCEPT", ipAddresses, "ip", allowRuleMaxCount, null, cancelToken));
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return Task.FromResult(false);
            }
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                string prefix = RulePrefix + (ruleNamePrefix ?? string.Empty);
                RunProcess("ipset", true, $"save > \"{tempFile}\"");
                bool inSet = false;
                foreach (string line in File.ReadLines(tempFile))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 1 && pieces[0].Equals("create", StringComparison.OrdinalIgnoreCase))
                    {
                        inSet = (pieces[1].StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
                    }
                    else if (inSet && pieces.Length > 2 && pieces[0] == "add")
                    {
                        yield return IPAddressRange.Parse(pieces[2]);
                    }
                }
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        public bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            ruleName = null;
            return EnumerateBannedIPAddresses().ToArray().Contains(ipAddress);
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            return EnumerateAllowedIPAddresses().ToArray().Contains(ipAddress);
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                RunProcess("ipset", true, $"save > \"{tempFile}\"");
                bool inBlockRule = true;
                foreach (string line in File.ReadLines(tempFile))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 1 && pieces[0].Equals("create", StringComparison.OrdinalIgnoreCase))
                    {
                        inBlockRule = (!pieces[1].Equals(AllowRuleName));
                    }
                    else if (inBlockRule && pieces.Length > 2 && pieces[0] == "add")
                    {
                        yield return pieces[2];
                    }
                }
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                RunProcess("ipset", true, $"save > \"{tempFile}\"");
                bool inAllow = true;
                foreach (string line in File.ReadLines(tempFile))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 1 && pieces[0].Equals("create", StringComparison.OrdinalIgnoreCase))
                    {
                        inAllow = (pieces[1].Equals(AllowRuleName));
                    }
                    else if (inAllow && pieces.Length > 2 && pieces[0] == "add")
                    {
                        yield return pieces[2];
                    }
                }
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        public virtual void Truncate()
        {
            RemoveAllTablesAndSets();
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
