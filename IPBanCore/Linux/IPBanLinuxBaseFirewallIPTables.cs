/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

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

// #define ENABLE_FIREWALL_PROFILING

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Linux firewall base class using iptables
    /// </summary>
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public abstract class IPBanLinuxBaseFirewallIPTables : IPBanBaseFirewall
    {
        /// <summary>
        /// Prefix put into log file for dropped packets
        /// </summary>
        public const string LogPacketPrefix = "X";

        private const string acceptAction = "ACCEPT";
        private const string dropAction = "DROP";

        private readonly AddressFamily addressFamily;
        private readonly string allowRuleName;

        private DateTime lastUpdate = IPBanService.UtcNow;

        /// <summary>
        /// Command for ip6tables
        /// </summary>
        protected const string ip6TablesProcess = "ip6tables";

        /// <summary>
        /// Is this ipv4 or ipv6 firewall?
        /// </summary>
        protected virtual bool IsIPV4 => true;

        /// <summary>
        /// Inet family
        /// </summary>
        protected virtual string INetFamily => IPBanLinuxIPSet.INetFamilyIPV4;

        /// <summary>
        /// Suffix for set files
        /// </summary>
        protected virtual string SetSuffix => ".set";

        /// <summary>
        /// Suffix for table files
        /// </summary>
        protected virtual string TableSuffix => ".tbl";

        /// <summary>
        /// IP tables process
        /// </summary>
        protected virtual string IpTablesProcess => "iptables";

        private readonly HashSet<string> allowRules = new(StringComparer.OrdinalIgnoreCase);

        private void RemoveAllTablesAndSets()
        {
            if (!IsIPV4)
            {
                return;
            }

            try
            {
                string dir = AppContext.BaseDirectory;
                foreach (string setFile in Directory.GetFiles(dir, "*.set")
                    .Union(Directory.GetFiles(dir, "*.tbl")
                    .Union(Directory.GetFiles(dir, "*.set6"))
                    .Union(Directory.GetFiles(dir, "*.tbl6"))))
                {
                    ExtensionMethods.FileDeleteWithRetry(setFile);
                }
                RunProcess(IpTablesProcess, true, "-F");
                RunProcess(ip6TablesProcess, true, "-F");
                IPBanLinuxIPSet.Reset();
            }
            catch
            {
            }
        }

        private void SaveSetsToDisk()
        {
            // ipset will save all the ipv6 sets as well, we don't need to run this command for the ipv6 firewall implementation
            if (IsIPV4)
            {
                string setFile = GetSetFileName();
                IPBanLinuxIPSet.SaveToFile(setFile);
            }
        }

        private void RestoreSetsFromDisk()
        {
            // ipv6 is an inner wrapper, do not do this for ipv6
            if (IsIPV4)
            {
                string setFile = GetSetFileName();
                IPBanLinuxIPSet.RestoreFromFile(setFile);
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

        /// <summary>
        /// Get table file name
        /// </summary>
        /// <returns>Table file name</returns>
        protected string GetTableFileName()
        {
            return Path.Combine(AppContext.BaseDirectory, "ipban" + TableSuffix);
        }

        /// <summary>
        /// Get set file name
        /// </summary>
        /// <returns>Set file name</returns>
        protected static string GetSetFileName()
        {
            return Path.Combine(AppContext.BaseDirectory, "ipban.set");
        }

        /// <summary>
        /// Execute a process
        /// </summary>
        /// <param name="program">Program</param>
        /// <param name="requireExitCode">Required exit code</param>
        /// <param name="commandLine">Command line</param>
        /// <param name="args">Args</param>
        /// <returns>Exit code</returns>
        public static int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
        {
            return RunProcess(program, requireExitCode, out _, commandLine, args);
        }

        /// <summary>
        /// Execute a process
        /// </summary>
        /// <param name="program">Program</param>
        /// <param name="requireExitCode">Required exit code</param>
        /// <param name="lines">Lines of output</param>
        /// <param name="commandLine">Command line</param>
        /// <param name="args">Args</param>
        /// <returns>Exit code</returns>
        public static int RunProcess(string program, bool requireExitCode, out IReadOnlyList<string> lines, string commandLine, params object[] args)
        {
            commandLine = string.Format(commandLine, args);
            string bash = "-c \"" + program + " " + commandLine.Replace("\"", "\\\"") + "\"";
            Logger.Debug("Running firewall process: {0} {1}", program, commandLine);
            using Process p = new()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = bash,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                }
            };
            p.Start();
            List<string> lineList = new();
            string line;
            while ((line = p.StandardOutput.ReadLine()) != null)
            {
                lineList.Add(line);
            }
            lines = lineList;
            if (!p.WaitForExit(60000))
            {
                Logger.Error("Process {0} {1} timed out", program, commandLine);
                p.Kill();
            }
            if (requireExitCode && p.ExitCode != 0)
            {
                Logger.Error("Process {0} {1} had exit code {2}", program, commandLine, p.ExitCode);
            }
            return p.ExitCode;
        }

        /// <summary>
        /// Create (or update) a firewall rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <param name="action">Action</param>
        /// <param name="allowedPorts">Allowd ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success</returns>
        /// <exception cref="OperationCanceledException">Creation was cancelled</exception>
        protected bool CreateOrUpdateRule(string ruleName, string action, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken)
        {
            // create or update the rule in iptables
            PortRange[] allowedPortsArray = allowedPorts?.ToArray();
            RunProcess(IpTablesProcess, true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string portString = " ";
            bool replaced = false;
            bool block = (action == dropAction);

            if (allowedPortsArray != null && allowedPortsArray.Length != 0)
            {
                string portList = (block ? IPBanFirewallUtility.GetPortRangeStringBlock(allowedPorts) :
                     IPBanFirewallUtility.GetPortRangeStringAllow(allowedPorts));
                portString = " -m multiport -p tcp --dports " + portList.Replace('-', ':') + " "; // iptables uses ':' instead of '-' for range
            }

            string ruleNameWithSpaces = " " + ruleName + " ";
            string rootCommand = $"INPUT ##RULENUM## -m state --state NEW -m set{portString}--match-set \"{ruleName}\" src -j";
            string logPrefix = LogPacketPrefix + ruleName + ": ";
            string logAction = $"LOG --log-prefix \"{logPrefix}\" --log-level 4";

            // if we have an existing rule, replace it
            foreach (string line in lines)
            {
                if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                {
                    // rule number is first piece of the line
                    int index = line.IndexOf(' ');
                    int ruleNum = int.Parse(line[..index]);

                    // replace the rule with the new info

                    if (LogPackets)
                    {
                        // replace log
                        RunProcess(IpTablesProcess, true, $"-R {rootCommand.Replace("##RULENUM##", ruleNum.ToStringInvariant())} {logAction}");
                        ruleNum++;
                    }

                    // replace drop
                    RunProcess(IpTablesProcess, true, $"-R {rootCommand.Replace("##RULENUM##", ruleNum.ToStringInvariant())} {action}");
                    replaced = true;
                    break;
                }
            }
            if (!replaced)
            {
                // add a new rule, for block add to end of list (lower priority) for allow add to begin of list (higher priority)
                string addCommand = (block ? "-A" : "-I");
                string newRootCommand = rootCommand.Replace("##RULENUM## ", string.Empty); // new rule, not using rule number

                if (LogPackets)
                {
                    // new log
                    RunProcess(IpTablesProcess, true, $"{addCommand} {newRootCommand} {logAction}");
                }

                // new drop
                RunProcess(IpTablesProcess, true, $"{addCommand} {newRootCommand} {action}");
            }

            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

            SaveTableToDisk();

            return true;
        }

        /// <summary>
        /// Update a firewall rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <param name="action">Action</param>
        /// <param name="ipAddresses">IP addresses</param>
        /// <param name="hashType">Hash type</param>
        /// <param name="allowPorts">Allowed ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success</returns>
        /// <exception cref="OperationCanceledException">Update rule cancelled</exception>
        protected bool UpdateRule(string ruleName, string action, IEnumerable<string> ipAddresses, string hashType,
            IEnumerable<PortRange> allowPorts, CancellationToken cancelToken)
        {

#if ENABLE_FIREWALL_PROFILING

            Stopwatch timer = Stopwatch.StartNew();

#endif

            string ipFileTemp = OSUtility.GetTempFileName();
            try
            {
                // create set file with full set info from passed values
                IPBanLinuxIPSet.UpsertSetFile(ipFileTemp, ruleName, hashType, INetFamily, ipAddresses, cancelToken);

                // restore the set fully
                bool result = IPBanLinuxIPSet.RestoreFromFile(ipFileTemp);
                CreateOrUpdateRule(ruleName, action, allowPorts, cancelToken);
                return result;
            }
            finally
            {
                ExtensionMethods.FileDeleteWithRetry(ipFileTemp);

#if ENABLE_FIREWALL_PROFILING

                timer.Stop();
                Logger.Warn("BlockIPAddressesDelta rule '{0}' took {1:0.00}ms with {2} ips",
                    ruleName, timer.Elapsed.TotalMilliseconds, ipAddresses.Count());

#endif

            }
        }

        /// <summary>
        /// Update a firewall rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <param name="action">Action</param>
        /// <param name="deltas">Delta IP addresses</param>
        /// <param name="hashType">Hash type</param>
        /// <param name="allowPorts">Allowed ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success</returns>
        /// <exception cref="OperationCanceledException">Update rule cancelled</exception>
        protected bool UpdateRuleDelta(string ruleName, string action, IEnumerable<IPBanFirewallIPAddressDelta> deltas, string hashType,
            IEnumerable<PortRange> allowPorts, CancellationToken cancelToken)
        {

#if ENABLE_FIREWALL_PROFILING

            Stopwatch timer = Stopwatch.StartNew();

#endif

            string ipFileTemp = OSUtility.GetTempFileName();
            try
            {
                // create set file with deltas
                IPBanLinuxIPSet.UpsertSetFileDelta(ipFileTemp, ruleName, hashType, INetFamily, deltas, cancelToken);

                // restore the deltas into the existing set
                bool result = IPBanLinuxIPSet.RestoreFromFile(ipFileTemp);
                CreateOrUpdateRule(ruleName, action, allowPorts, cancelToken);
                return result;
            }
            finally
            {
                ExtensionMethods.FileDeleteWithRetry(ipFileTemp);

#if ENABLE_FIREWALL_PROFILING

                timer.Stop();
                Logger.Warn("BlockIPAddressesDelta rule '{0}' took {1:0.00}ms with {2} ips",
                    ruleName, timer.Elapsed.TotalMilliseconds, deltas.Count());

#endif

            }
        }

        /// <inheritdoc />
        protected override void OnDispose()
        {
            base.OnDispose();

            SaveSetsToDisk();
            SaveTableToDisk();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public IPBanLinuxBaseFirewallIPTables(string rulePrefix = null) : base(rulePrefix)
        {
            addressFamily = (IsIPV4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6);
            allowRuleName = AllowRulePrefix + "0";
            RestoreSetsFromDisk();
            RestoreTablesFromDisk();
        }

        /// <inheritdoc />
        public override Task Update(CancellationToken cancelToken)
        {
            base.Update(cancelToken);

            // flush all sets to disk one per minute
            DateTime now = IPBanService.UtcNow;
            if ((now - lastUpdate) > TimeSpan.FromMinutes(1.0))
            {
                lastUpdate = now;
                SaveSetsToDisk();
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
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
                    yield return line[start..pos];
                }
            }
        }

        /// <summary>
        /// Determine if rule is an allow rule
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>True if allow rule, false if block rule</returns>
        public bool IsAllowRule(string ruleName)
        {
            return allowRules.Contains(ruleName);
        }

        /// <inheritdoc />
        public override bool DeleteRule(string ruleName)
        {
            RunProcess(IpTablesProcess, true, out IReadOnlyList<string> lines, "-L --line-numbers");
            string ruleNameWithSpaces = " " + ruleName + " ";
            allowRules.Remove(ruleName);

            foreach (string line in lines)
            {
                if (line.Contains(ruleNameWithSpaces, StringComparison.OrdinalIgnoreCase))
                {
                    // rule number is first piece of the line
                    int index = line.IndexOf(' ');
                    int ruleNum = int.Parse(line[..index]);

                    // remove the rule from iptables
                    RunProcess(IpTablesProcess, true, $"-D INPUT {ruleNum}");
                    SaveTableToDisk();

                    // remove the set
                    IPBanLinuxIPSet.DeleteSet(ruleName);

                    return true;
                }
            }
            return false;
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            try
            {
                string ruleName = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix);
                return Task.FromResult(UpdateRule(ruleName, dropAction, ipAddresses, IPBanLinuxIPSet.HashTypeSingleIP, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> deltas, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            try
            {
                string ruleName = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix);
                return Task.FromResult(UpdateRuleDelta(ruleName, dropAction, deltas, IPBanLinuxIPSet.HashTypeSingleIP, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            ruleNamePrefix.ThrowIfNullOrWhiteSpace();

            try
            {
                return Task.FromResult(UpdateRule(RulePrefix + ruleNamePrefix, dropAction, ranges.Select(r => r.ToCidrString()),
                    IPBanLinuxIPSet.HashTypeNetwork, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            try
            {
                return Task.FromResult(UpdateRule(allowRuleName, acceptAction, ipAddresses, IPBanLinuxIPSet.HashTypeSingleIP, null, cancelToken));
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            try
            {
                ruleNamePrefix.ThrowIfNullOrWhiteSpace();
                string ruleName = RulePrefix + ruleNamePrefix;
                allowRules.Add(ruleName);
                return Task.FromResult(UpdateRule(ruleName, acceptAction, ipAddresses.Select(r => r.ToCidrString()),
                    IPBanLinuxIPSet.HashTypeNetwork, allowedPorts, cancelToken));
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc />
        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            string prefix = RulePrefix + (ruleNamePrefix ?? string.Empty);
            return IPBanLinuxIPSet
                .EnumerateSets()
                .Where(s => s.SetName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Range);
        }

        /// <inheritdoc />
        public override bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            if (!IsIPAddressAllowed(ipAddress) &&
                System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipObj))
            {
                foreach (var item in IPBanLinuxIPSet.EnumerateSets()
                    .Where(s => !allowRules.Contains(s.SetName)))
                {
                    if (item.Range.Contains(ipObj))
                    {
                        ruleName = item.SetName;
                        return true;
                    }
                }
            }
            ruleName = null;
            return false;
        }

        /// <inheritdoc />
        public override bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            if (System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipObj))
            {
                foreach (var item in IPBanLinuxIPSet.EnumerateSets()
                    .Where(s => allowRules.Contains(s.SetName)))
                {
                    if (item.Range.Contains(ipObj))
                    {
                        return true;
                    }
                }
            }
            return false;
        }


        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return IPBanLinuxIPSet
                .EnumerateSets()
                .Where(s => !allowRules.Contains(s.SetName))
                .Select(s => s.Range.ToString());
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return IPBanLinuxIPSet
                .EnumerateSets()
                .Where(s => allowRules.Contains(s.SetName))
                .Select(s => s.Range.ToString());
        }

        /// <inheritdoc />
        public override void Truncate()
        {
            RemoveAllTablesAndSets();
        }

        /// <summary>
        /// Whether to log packets affected by rules from this firewall
        /// </summary>
        public bool LogPackets { get; set; }
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
