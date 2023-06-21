﻿/*
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
        /// Hash size
        /// </summary>
        protected const int hashSize = 1024;

        /// <summary>
        /// Max block rule count
        /// </summary>
        protected const int blockRuleMaxCount = 2097152;
        
        /// <summary>
        /// Max allow rule count
        /// </summary>
        protected const int allowRuleMaxCount = 8192;

        /// <summary>
        /// Max block rule range count
        /// </summary>
        protected const int blockRuleRangesMaxCount = 4194304;

        /// <summary>
        /// Single ip type
        /// </summary>
        protected const string hashTypeSingleIP = "ip";

        /// <summary>
        /// Cidr mask type
        /// </summary>
        protected const string hashTypeCidrMask = "net";

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
        protected virtual string INetFamily => "inet";

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
                RunProcess("ipset", true, "destroy");
            }
            catch
            {
            }
        }

        private static void DeleteSet(string ruleName)
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
            // ipset will save all the ipv6 sets as well, we don't need to run this command for the ipv6 firewall implementation
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
        protected static int RunProcess(string program, bool requireExitCode, string commandLine, params object[] args)
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
        protected static int RunProcess(string program, bool requireExitCode, out IReadOnlyList<string> lines, string commandLine, params object[] args)
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
        /// <param name="hashType">Hash type</param>
        /// <param name="maxCount">Max count for rule</param>
        /// <param name="allowedPorts">Allowd ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success</returns>
        /// <exception cref="OperationCanceledException">Creation was cancelled</exception>
        protected bool CreateOrUpdateRule(string ruleName, string action, string hashType, int maxCount, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken)
        {
            if (cancelToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancelToken);
            }

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
        /// <param name="maxCount">Max count</param>
        /// <param name="allowPorts">Allowed ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success</returns>
        /// <exception cref="OperationCanceledException">Update rule cancelled</exception>
        protected bool UpdateRule(string ruleName, string action, IEnumerable<string> ipAddresses, string hashType, int maxCount,
            IEnumerable<PortRange> allowPorts, CancellationToken cancelToken)
        {

#if ENABLE_FIREWALL_PROFILING

            Stopwatch timer = Stopwatch.StartNew();

#endif

            string ipFileTemp = OSUtility.GetTempFileName();
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
                                if (hashType != hashTypeCidrMask || range.Single)
                                {
                                    writer.WriteLine($"add {ruleName} {range.Begin} -exist");
                                }
                                else if (range.GetPrefixLength(false) < 0)
                                {
                                    // attempt to write the ips in this range if the count is low enough
                                    if (range.GetCount() < 128)
                                    {
                                        foreach (System.Net.IPAddress ip in range)
                                        {
                                            writer.WriteLine($"add {ruleName} {ip} -exist");
                                        }
                                    }
                                    else
                                    {
                                        Logger.Debug("Skipped writing non-cidr range {0} because of too many ips", range);
                                    }
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
        /// <param name="maxCount">Max count</param>
        /// <param name="deleteRule">Will drop the rule and matching set before creating the rule and set, use this is you don't care to update the rule and set in place</param>
        /// <param name="allowPorts">Allowed ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success</returns>
        /// <exception cref="OperationCanceledException">Update rule cancelled</exception>
        protected bool UpdateRuleDelta(string ruleName, string action, IEnumerable<IPBanFirewallIPAddressDelta> deltas, string hashType,
            int maxCount, bool deleteRule, IEnumerable<PortRange> allowPorts, CancellationToken cancelToken)
        {

#if ENABLE_FIREWALL_PROFILING

            Stopwatch timer = Stopwatch.StartNew();

#endif

            string ipFileTemp = OSUtility.GetTempFileName();
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
                                    if (range.Single)
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
                                    if (range.Single)
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
                    DeleteSet(ruleName);

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
                return Task.FromResult(UpdateRule(ruleName, dropAction, ipAddresses, hashTypeSingleIP, blockRuleMaxCount, allowedPorts, cancelToken));
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
                return Task.FromResult(UpdateRuleDelta(ruleName, dropAction, deltas, hashTypeSingleIP, blockRuleMaxCount, false, allowedPorts, cancelToken));
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
                return Task.FromResult(UpdateRule(RulePrefix + ruleNamePrefix, dropAction, ranges.Select(r => r.ToCidrString()), hashTypeCidrMask, blockRuleRangesMaxCount, allowedPorts, cancelToken));
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
                return Task.FromResult(UpdateRule(allowRuleName, acceptAction, ipAddresses, hashTypeSingleIP, allowRuleMaxCount, null, cancelToken));
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
                return Task.FromResult(UpdateRule(ruleName, acceptAction, ipAddresses.Select(r => r.ToCidrString()), hashTypeCidrMask, blockRuleMaxCount, allowedPorts, cancelToken));
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
            string tempFile = OSUtility.GetTempFileName();
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
                ExtensionMethods.FileDeleteWithRetry(tempFile);
            }
        }

        /// <inheritdoc />
        public override bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            if (System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipObj))
            {
                foreach (var ip in EnumerateBannedIPAddresses())
                {
                    if (IPAddressRange.TryParse(ip, out IPAddressRange range) && range.Contains(ipObj))
                    {
                        ruleName = lastBlockRuleEnumerated;
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
                foreach (var ip in EnumerateAllowedIPAddresses())
                {
                    if (IPAddressRange.TryParse(ip, out IPAddressRange range) && range.Contains(ipObj))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private string lastBlockRuleEnumerated;

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            string tempFile = OSUtility.GetTempFileName();
            lastBlockRuleEnumerated = null;
            try
            {
                RunProcess("ipset", true, $"save > \"{tempFile}\"");
                bool inBlockRule = true;
                foreach (string line in File.ReadLines(tempFile))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 1 && pieces[0].Equals("create", StringComparison.OrdinalIgnoreCase))
                    {
                        inBlockRule = (!pieces[1].Equals(allowRuleName) &&
                            (pieces[1].StartsWith(BlockRulePrefix) || pieces[1].StartsWith(RulePrefix + "6_Block_")));
                        if (inBlockRule)
                        {
                            lastBlockRuleEnumerated = pieces[1];
                        }
                        else
                        {
                            lastBlockRuleEnumerated = null;
                        }
                    }
                    else if (inBlockRule && pieces.Length > 2 && pieces[0] == "add")
                    {
                        yield return pieces[2];
                    }
                }
            }
            finally
            {
                ExtensionMethods.FileDeleteWithRetry(tempFile);
            }
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            string tempFile = OSUtility.GetTempFileName();
            try
            {
                RunProcess("ipset", true, $"save > \"{tempFile}\"");
                bool inAllow = true;
                foreach (string line in File.ReadLines(tempFile))
                {
                    string[] pieces = line.Split(' ');
                    if (pieces.Length > 1 && pieces[0].Equals("create", StringComparison.OrdinalIgnoreCase))
                    {
                        inAllow = (pieces[1].Equals(allowRuleName));
                    }
                    else if (inAllow && pieces.Length > 2 && pieces[0] == "add")
                    {
                        yield return pieces[2];
                    }
                }
            }
            finally
            {
                ExtensionMethods.FileDeleteWithRetry(tempFile);
            }
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
