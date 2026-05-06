/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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

#region Imports

using DigitalRuby.IPBanCore.Windows.COM;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Helper class for Windows firewall and banning ip addresses.
    /// </summary>
    [RequiredOperatingSystem(OSUtility.Windows, PriorityEnvironmentVariable = "IPBanPro_WindowsFirewallPriority")]
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public class IPBanWindowsFirewall : IPBanBaseFirewall
    {
        /// <summary>
        /// Max number of ip addresses per rule
        /// </summary>
        public const int MaxIpAddressesPerRule = 1000;

        // DO NOT CHANGE THESE CONST AND READONLY FIELDS! ***********************************************************************************
        private const string clsidFwPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        private const string clsidFwRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "jjxtra")]
        private static readonly INetFwPolicy2 policy = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid(clsidFwPolicy2))) as INetFwPolicy2;
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "jjxtra")]
        private static readonly INetFwMgr manager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "jjxtra")]
        private static readonly Type ruleType = Type.GetTypeFromCLSID(new Guid(clsidFwRule));
        private static readonly char[] firewallEntryDelimiters = ['/', '-'];

        // Dedicated lock object for serializing access to the COM policy and its Rules
        // collection. We don't lock on `policy` directly because (a) it's a COM RCW so locking
        // on it is fragile if the COM init ever fails and the field is null, and (b) using a
        // plain object makes the synchronization boundary explicit. Every policy.Rules access
        // in this class must happen inside lock(policyLock).
        private static readonly object policyLock = new();
        // **********************************************************************************************************************************

        /// <summary>
        /// Release a COM RCW reference for a fetched INetFwRule. Any rule obtained via
        /// policy.Rules.Item(name) or by iterating policy.Rules carries a managed wrapper
        /// over a COM object — failing to release it leaves the underlying RPC handle in
        /// the COM apartment until GC. At firewall scales (thousands of rules iterated each
        /// cycle) those handles accumulate until the firewall service refuses new calls and
        /// the process must be restarted.
        /// Public for testability — handles null and non-COM objects safely.
        /// </summary>
        public static void ReleaseRule(INetFwRule rule)
        {
            if (rule is null)
            {
                return;
            }
            try
            {
                if (Marshal.IsComObject(rule))
                {
                    Marshal.FinalReleaseComObject(rule);
                }
            }
            catch
            {
                // best effort — RCW may have already been released by another path
            }
        }

        /// <summary>
        /// A list of INetFwRule COM objects that releases each RCW on Dispose.
        /// Callers MUST dispose (via using or explicit Dispose) to avoid leaking.
        /// Public for testability.
        /// </summary>
        public sealed class RuleList : List<INetFwRule>, IDisposable
        {
            private bool disposed;

            /// <inheritdoc />
            public void Dispose()
            {
                if (disposed)
                {
                    return;
                }
                disposed = true;
                for (int i = 0; i < Count; i++)
                {
                    ReleaseRule(this[i]);
                }
                Clear();
            }
        }
        // **********************************************************************************************************************************

        private static string CreateRuleStringForIPAddresses(IReadOnlyList<string> ipAddresses, int index, int count)
        {
            if (count == 0 || index >= ipAddresses.Count)
            {
                return string.Empty;
            }

            // don't overrun array
            count = Math.Min(count, ipAddresses.Count - index);

            StringBuilder b = new(count * 16);
            foreach (string ipAddress in ipAddresses.Skip(index).Take(count))
            {
                if (ipAddress.TryNormalizeIPAddress(out string firewallIPAddress))
                {
                    b.Append(firewallIPAddress);
                    b.Append(',');
                }
            }
            if (b.Length != 0)
            {
                // remove ending comma
                b.Length--;
            }

            return b.ToString();
        }

        private static bool GetOrCreateRule(string ruleName, string remoteIPAddresses, NetFwAction action,
            IEnumerable<PortRange> allowedPorts = null, string description = null)
        {
            remoteIPAddresses = (remoteIPAddresses ?? string.Empty).Trim();
            bool emptyIPAddressString = string.IsNullOrWhiteSpace(remoteIPAddresses) || remoteIPAddresses == "*";
            bool ruleNeedsToBeAdded = false;

            lock (policyLock)
            {
                INetFwRule rule = null;
            try_again:
                try
                {
                    rule = policy.Rules.Item(ruleName);
                }
                catch
                {
                    // ignore exception, assume does not exist
                }
                if (rule is null)
                {
                    var disabled = description is not null && description.Contains("###DISABLED###");
                    description = description?.Replace("###DISABLED###", string.Empty);
                    var ruleDescription = description ?? "Automatically created by IPBan";
                    rule = Activator.CreateInstance(ruleType) as INetFwRule;
                    rule.Name = ruleName;
                    rule.Description = ruleDescription;
                    rule.Enabled = !disabled;
                    rule.Action = action;
                    rule.Direction = NetFwRuleDirection.Inbound;
                    rule.EdgeTraversal = false;
                    rule.Grouping = "IPBan";
                    rule.LocalAddresses = "*";
                    rule.Profiles = int.MaxValue; // all
                    ruleNeedsToBeAdded = true;
                }

                // do not ever set an empty string, Windows treats this as * which means everything
                if (!emptyIPAddressString)
                {
                    try
                    {
                        PortRange[] allowedPortsArray = (allowedPorts?.ToArray());
                        if (allowedPortsArray != null && allowedPortsArray.Length != 0)
                        {
                            rule.Protocol = (int)NetFwIPProtocol.TCP;
                            string localPorts;
                            if (action == NetFwAction.Block)
                            {
                                localPorts = IPBanFirewallUtility.GetPortRangeStringBlock(allowedPortsArray);
                            }
                            else
                            {
                                localPorts = IPBanFirewallUtility.GetPortRangeStringAllow(allowedPortsArray);
                            }
                            rule.LocalPorts = localPorts;
                        }
                        else
                        {
                            try
                            {
                                rule.Protocol = (int)NetFwIPProtocol.Any;
                            }
                            catch
                            {
                                // failed to set protocol to any, we are switching from tcp back to any without ports, the only option is to
                                //  recreate the rule
                                if (!ruleNeedsToBeAdded)
                                {
                                    policy.Rules.Remove(ruleName);
                                    // release the stale rule before re-fetching to avoid leaking its COM RCW
                                    ReleaseRule(rule);
                                    rule = null;
                                    ruleNeedsToBeAdded = false;
                                    goto try_again;
                                }
                            }
                        }
                        rule.RemoteAddresses = (remoteIPAddresses == "0.0.0.0/0,::/0" ? "*" : remoteIPAddresses);
                    }
                    catch (Exception ex)
                    {
                        // if something failed, do not create the rule
                        emptyIPAddressString = true;
                        Logger.Error(ex, "Failed to set Windows Firewall ip addresses: {0}", remoteIPAddresses);
                    }
                }

                if (emptyIPAddressString || string.IsNullOrWhiteSpace(rule.RemoteAddresses) || (rule.RemoteAddresses == "*" && remoteIPAddresses != "0.0.0.0/0,::/0"))
                {
                    // if no ip addresses, remove the rule as it will allow or block everything with an empty RemoteAddresses string
                    try
                    {
                        rule = null;
                        policy.Rules.Remove(ruleName);
                    }
                    catch
                    {
                    }
                }
                else if (ruleNeedsToBeAdded)
                {
                    policy.Rules.Add(rule);
                }
                bool created = (rule != null);
                // release our local COM reference; if we Added, the policy holds its own reference
                ReleaseRule(rule);
                return created;
            }
        }

        private static void CreateBlockRule(IReadOnlyList<string> ipAddresses, int index, int count, string ruleName,
            IEnumerable<PortRange> allowedPorts = null, string description = null)
        {
            string remoteIpString = CreateRuleStringForIPAddresses(ipAddresses, index, count);
            GetOrCreateRule(ruleName, remoteIpString, NetFwAction.Block, allowedPorts, description);
        }

        private static void CreateAllowRule(IReadOnlyList<string> ipAddresses, int index, int count, string ruleName,
            IEnumerable<PortRange> allowedPorts = null, string description = null)
        {
            string remoteIpString = CreateRuleStringForIPAddresses(ipAddresses, index, count);
            GetOrCreateRule(ruleName, remoteIpString, NetFwAction.Allow, allowedPorts, description);
        }

        private void MigrateOldDefaultRuleNames()
        {
            // migrate old default rule names to new names — release each fetched rule's RCW
            // after we're done renaming it, otherwise a rolling migration leaks one COM handle
            // per rule per service start.
            INetFwRule rule;
            for (int i = 0; ; i += MaxIpAddressesPerRule)
            {
                rule = null;
                lock (policyLock)
                {
                    try
                    {
                        try
                        {
                            // migrate really old style
                            rule = policy.Rules.Item("IPBan_BlockIPAddresses_" + i.ToString(CultureInfo.InvariantCulture));
                        }
                        catch
                        {
                            // not exist, that is OK
                        }
                        // migrate IPBan_0 style to IPBan_Block_0 style
                        rule ??= policy.Rules.Item("IPBan_" + i.ToString(CultureInfo.InvariantCulture));
                        rule.Name = BlockRulePrefix + i.ToString(CultureInfo.InvariantCulture);
                    }
                    catch
                    {
                        // ignore exception, assume does not exist
                        ReleaseRule(rule);
                        break;
                    }
                }
                ReleaseRule(rule);
            }
            rule = null;
            lock (policyLock)
            {
                try
                {
                    rule = policy.Rules.Item("IPBan_BlockIPAddresses_AllowIPAddresses");
                    rule.Name = AllowRulePrefix + "0";
                }
                catch
                {
                    // ignore exception, assume does not exist
                }
            }
            ReleaseRule(rule);
        }

        private static bool DeleteRules(string ruleNamePrefix, int startIndex = 0)
        {
            try
            {
                using var matchingRules = EnumerateRulesMatchingPrefix(ruleNamePrefix);
                lock (policyLock)
                {
                    foreach (INetFwRule rule in matchingRules)
                    {
                        try
                        {
                            Match match = Regex.Match(rule.Name, $"^{ruleNamePrefix}(?<num>[0-9]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                            if (match.Success && int.TryParse(match.Groups["num"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int num) && num >= startIndex)
                            {
                                policy.Rules.Remove(rule.Name);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                // matchingRules.Dispose() releases all enumerated INetFwRule COM RCWs
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error("Error deleting rules", ex);
                return false;
            }
        }

        // Returns a snapshot of rules whose name starts with the prefix. The caller MUST
        // dispose the returned RuleList (use `using var rules = ...`) so each INetFwRule's
        // COM RCW is released — otherwise every call leaks one handle per matching rule.
        // The policy lock is held for the entire enumeration because the underlying COM
        // enumerator is not thread-safe; a concurrent Add/Remove from another thread can
        // crash the iterator mid-loop.
        private static RuleList EnumerateRulesMatchingPrefix(string ruleNamePrefix)
        {
            // powershell example
            // (New-Object -ComObject HNetCfg.FwPolicy2).rules | Where-Object { $_.Name -match '^prefix' } | ForEach-Object { Write-Output "$($_.Name)" }
            // TODO: Revisit COM interface in .NET core 3.0
            RuleList rules = new();
            bool matchAll = (string.IsNullOrWhiteSpace(ruleNamePrefix) || ruleNamePrefix == "*");
            IntPtr bufferLengthPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<int>());
            object[] results = new object[64];
            int count;
            try
            {
                lock (policyLock)
                {
                    var e = policy.Rules.GetEnumeratorVariant();
                    try
                    {
                        do
                        {
                            e.Next(results.Length, results, bufferLengthPointer);
                            count = Marshal.ReadInt32(bufferLengthPointer);
                            for (int i = 0; i < count; i++)
                            {
                                object o = results[i];
                                if (o is INetFwRule rule)
                                {
                                    if (matchAll || rule.Name.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase))
                                    {
                                        rules.Add(rule);
                                    }
                                    else
                                    {
                                        // we own this RCW since enumeration handed it to us — release the ones we filter out
                                        ReleaseRule(rule);
                                    }
                                }
                                // null entries are returned at the end of the buffer; nothing to release
                                results[i] = null;
                            }
                        }
                        while (count == results.Length);
                    }
                    finally
                    {
                        if (e is not null && Marshal.IsComObject(e))
                        {
                            try { Marshal.FinalReleaseComObject(e); } catch { /* best effort */ }
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(bufferLengthPointer);
            }

            rules.Sort((rule1, rule2) =>
            {
                Match match1 = Regex.Match(rule1.Name, "_(?<index>[0-9]+)$");
                Match match2 = Regex.Match(rule2.Name, "_(?<index>[0-9]+)$");
                if (match1.Success && match2.Success)
                {
                    string value1 = match1.Groups["index"].Value.PadLeft(9, '0');
                    string value2 = match2.Groups["index"].Value.PadLeft(9, '0');
                    return value1.CompareTo(value2);
                }
                return rule1.Name.CompareTo(rule2.Name);
            });
            return rules;

            /*
            System.Diagnostics.Process p = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    Arguments = "advfirewall firewall show rule name=all",
                    CreateNoWindow = true,
                    FileName = "netsh.exe",
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                }
            };
            p.Start();
            string line;
            string ruleName;
            INetFwRule rule;
            Regex regex = new Regex(": +" + prefix + ".*");
            Match match;

            while ((line = p.StandardOutput.ReadLine()) != null)
            {
                match = regex.Match(line);
                if (match.Success)
                {
                    ruleName = match.Value.Trim(' ', ':');
                    rule = null;
                    try
                    {
                        rule = policy.Rules.Item(ruleName);
                    }
                    catch
                    {
                    }
                    if (rule != null)
                    {
                        yield return rule;
                    }
                }
            }
            */
        }

        private static Task<bool> BlockOrAllowIPAddresses(string ruleNamePrefix, bool block, IEnumerable<string> ipAddresses,
            IEnumerable<PortRange> allowedPorts = null, string description = null, CancellationToken cancelToken = default)
        {

#if ENABLE_FIREWALL_PROFILING

            Stopwatch timer = Stopwatch.StartNew();

#endif

            int i = 0;
            string prefix = ruleNamePrefix.TrimEnd('_') + "_";

            try
            {
                List<string> ipAddressesList = [];
                foreach (string ipAddress in ipAddresses)
                {
                    cancelToken.ThrowIfCancellationRequested();
                    ipAddressesList.Add(ipAddress);
                    if (ipAddressesList.Count == MaxIpAddressesPerRule)
                    {
                        if (block)
                        {
                            CreateBlockRule(ipAddressesList, 0, MaxIpAddressesPerRule, prefix + i.ToStringInvariant(), allowedPorts);
                        }
                        else
                        {
                            CreateAllowRule(ipAddressesList, 0, MaxIpAddressesPerRule, prefix + i.ToStringInvariant(), allowedPorts);
                        }
                        i += MaxIpAddressesPerRule;
                        ipAddressesList.Clear();
                    }
                }
                cancelToken.ThrowIfCancellationRequested();
                if (ipAddressesList.Count != 0)
                {
                    if (block)
                    {
                        CreateBlockRule(ipAddressesList, 0, MaxIpAddressesPerRule, prefix + i.ToStringInvariant(), allowedPorts, description);
                    }
                    else
                    {
                        CreateAllowRule(ipAddressesList, 0, MaxIpAddressesPerRule, prefix + i.ToStringInvariant(), allowedPorts, description);
                    }
                    i += MaxIpAddressesPerRule;
                }
                DeleteRules(prefix, i);
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
                return Task.FromResult(false);
            }
            finally
            {

#if ENABLE_FIREWALL_PROFILING

                timer.Stop();
                Logger.Warn("Block ip addresses rule '{0}' took {1:0.00}ms with {2} ips",
                    prefix, timer.Elapsed.TotalMilliseconds, i);

#endif

            }
        }

        /// <summary>
        /// Throw an exception if Windows firewall is disabled
        /// </summary>
        public static void ThrowExceptionIfWindowsFirewallIsDisabled()
        {
            // netsh advfirewall show allprofiles state
            if (!policy.get_FirewallEnabled(NetFwProfileType2.Domain) &&
                !policy.get_FirewallEnabled(NetFwProfileType2.Private) &&
                !policy.get_FirewallEnabled(NetFwProfileType2.Public) &&
                !manager.LocalPolicy.CurrentProfile.FirewallEnabled)
            {
                // read firewall state from powershell script
                ProcessStartInfo psScript = new("powershell", "Get-NetfirewallProfile -PolicyStore ActiveStore")
                {
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using Process psProcess = Process.Start(psScript);
                psProcess.WaitForExit();
                string text = psProcess.StandardOutput.ReadToEnd();
                if (!Regex.IsMatch(text, @"enabled\s*:\s*true", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                {
                    throw new ApplicationException("Windows firewall is currently disabled, please enable Windows firewall. Public, Private and Domain profiles were checked for active state.");
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public IPBanWindowsFirewall(string rulePrefix = null) : base(rulePrefix)
        {
            ThrowExceptionIfWindowsFirewallIsDisabled();
            MigrateOldDefaultRuleNames();
        }

        /// <inheritdoc />
        public override IPBanMemoryFirewall Compile()
        {
            IPBanMemoryFirewall mem = new(RulePrefix);

            try
            {
                lock (policyLock)
                {
                    foreach (INetFwRule rule in policy.Rules)
                    {
                        try
                        {
                            if (rule is not null &&
                                !string.IsNullOrWhiteSpace(rule.Name) &&
                                !string.IsNullOrWhiteSpace(rule.RemoteAddresses) &&
                                rule.Name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                            {
                                var ips = rule.RemoteAddresses.Split(',').Select(r => IPAddressRange.Parse(r));
                                var ports = (rule.LocalPorts ?? string.Empty).Split(',').Select(p => PortRange.Parse(p));
                                if (rule.Action == NetFwAction.Allow)
                                {
                                    mem.AllowIPAddresses(rule.Name, ips, ports);
                                }
                                else
                                {
                                    // firewall methods for now, always take allow ports, so we need to invert block ports to allow
                                    // the firewall block method will invert them back to block ports
                                    var invertedPorts = IPBanFirewallUtility.InvertPortRanges(ports);
                                    mem.BlockIPAddresses(rule.Name, ips, invertedPorts);
                                }
                            }
                        }
                        catch (Exception inner)
                        {
                            // in case COM api throws
                            if (inner is not OperationCanceledException)
                            {
                                Logger.Error(inner);
                            }
                        }
                        finally
                        {
                            // Each rule from this foreach is a fresh COM RCW that we own; release
                            // it before the next iteration so a Compile over a large firewall
                            // doesn't accumulate handles until exhaustion.
                            ReleaseRule(rule);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error(ex);
                }
            }
            return mem;
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            string prefix = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix).TrimEnd('_') + "_";
            return BlockOrAllowIPAddresses(prefix, true, ipAddresses, allowedPorts, null, cancelToken);
        }

        /// <summary>
        /// Block ip addresses with a description
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix</param>
        /// <param name="ipAddresses">IP addresses</param>
        /// <param name="allowedPorts">Allowed ports</param>
        /// <param name="description">Description</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Result</returns>
        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, string description = null, CancellationToken cancelToken = default)
        {
            string prefix = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix).TrimEnd('_') + "_";
            return BlockOrAllowIPAddresses(prefix, true, ipAddresses, allowedPorts, description, cancelToken);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {

#if ENABLE_FIREWALL_PROFILING

            Stopwatch timer = Stopwatch.StartNew();

#endif

            string prefix = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix).TrimEnd('_') + "_";
            int ruleIndex;
            // Snapshot just the rule names and remote-address strings into managed memory, then
            // dispose the RuleList immediately. The rest of the algorithm only needs the strings;
            // holding live COM references across it would pin one RCW per rule for the whole
            // delta computation.
            string[] ruleNames;
            List<HashSet<string>> remoteIPAddresses = [];
            List<bool> ruleChanges = [];
            using (var matchedRules = EnumerateRulesMatchingPrefix(prefix))
            {
                ruleNames = new string[matchedRules.Count];
                for (int i = 0; i < matchedRules.Count; i++)
                {
                    ruleNames[i] = matchedRules[i].Name;
                    string[] ipList = (matchedRules[i].RemoteAddresses ?? string.Empty).Split(',');
                    HashSet<string> ipSet = [];
                    foreach (string ip in ipList)
                    {
                        // trim out submask
                        int pos = ip.IndexOfAny(firewallEntryDelimiters);
                        ipSet.Add(pos >= 0 ? ip[..pos] : ip);
                    }
                    remoteIPAddresses.Add(ipSet);
                    ruleChanges.Add(false);
                }
            }
            // matchedRules disposed here — all INetFwRule RCWs released
            List<IPBanFirewallIPAddressDelta> deltas = ipAddresses.ToList();
            int deltasCount = deltas.Count;
            for (int deltaIndex = deltas.Count - 1; deltaIndex >= 0; deltaIndex--)
            {
                IPBanFirewallIPAddressDelta delta = deltas[deltaIndex];
                if (delta.Added)
                {
                    if (remoteIPAddresses.Any(set => set.Contains(delta.IPAddress)))
                    {
                        // no change, a set already has the ip
                        deltas.RemoveAt(deltaIndex);
                        continue;
                    }
                    else
                    {
                        // try to find a set with an availble slot
                        for (int setIndex = 0; setIndex < remoteIPAddresses.Count; setIndex++)
                        {
                            if (remoteIPAddresses[setIndex].Count < MaxIpAddressesPerRule)
                            {
                                remoteIPAddresses[setIndex].Add(delta.IPAddress);
                                deltas.RemoveAt(deltaIndex);
                                ruleChanges[setIndex] = true;
                                break;
                            }
                        }
                    }
                }
                else
                {
                    for (int setIndex = 0; setIndex < remoteIPAddresses.Count; setIndex++)
                    {
                        if (remoteIPAddresses[setIndex].Remove(delta.IPAddress))
                        {
                            ruleChanges[setIndex] = true;
                            break;
                        }
                    }
                    deltas.RemoveAt(deltaIndex);
                }
            }

            // any remaining deltas for adding need to go in new rules if they did not fit in the existing rules
            // remaining deltas are guaranteed to be adds
            string[] remainingIPAddresses = deltas.Select(d => d.IPAddress).Where(ip => IPAddress.TryParse(ip, out _)).ToArray();
            for (int i = 0; i < remainingIPAddresses.Length; i += MaxIpAddressesPerRule)
            {
                remoteIPAddresses.Add(new HashSet<string>(remainingIPAddresses.Skip(i).Take(MaxIpAddressesPerRule)));
                ruleChanges.Add(true);
            }

            // update the rules
            ruleIndex = 0;
            for (int i = 0; i < remoteIPAddresses.Count; i++)
            {
                if (ruleChanges[i])
                {
                    string name = (i < ruleNames.Length ? ruleNames[i] : prefix + ruleIndex.ToStringInvariant());
                    GetOrCreateRule(name, string.Join(',', remoteIPAddresses[i]), NetFwAction.Block, allowedPorts);
                }
                ruleIndex += MaxIpAddressesPerRule;
            }

#if ENABLE_FIREWALL_PROFILING

            timer.Stop();
            Logger.Warn("BlockIPAddressesDelta rule '{0}' took {1:0.00}ms with {2} ips",
                prefix, timer.Elapsed.TotalMilliseconds, deltasCount);

#endif

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            ruleNamePrefix.ThrowIfNullOrWhiteSpace();
            return BlockOrAllowIPAddresses(RulePrefix + ruleNamePrefix, true, ranges.Select(i => i.ToCidrString()),
                allowedPorts, null, cancelToken);
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            return BlockOrAllowIPAddresses(AllowRulePrefix, false, ipAddresses, null, null, cancelToken);
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            ruleNamePrefix.ThrowIfNullOrWhiteSpace();
            return BlockOrAllowIPAddresses(RulePrefix + ruleNamePrefix, false, ipAddresses.Select(i => i.ToCidrString()),
                allowedPorts, null, cancelToken);
        }

        /// <inheritdoc />
        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            string prefix = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? RulePrefix : RulePrefix + ruleNamePrefix);
            // Materialize the names with ToList() before the using block disposes the RuleList.
            // A lazy LINQ chain would be evaluated only when the consumer iterated it — by then
            // the COM rules would already be released and Name reads would crash.
            using var matchedRules = EnumerateRulesMatchingPrefix(prefix);
            return matchedRules.OrderBy(r => r.Name).Select(r => r.Name).ToList();
        }

        /// <inheritdoc />
        public override bool DeleteRule(string ruleName)
        {
            INetFwRule rule = null;
            try
            {
                lock (policyLock)
                {
                    rule = policy.Rules.Item(ruleName);
                    policy.Rules.Remove(rule.Name);
                }
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                ReleaseRule(rule);
            }
        }

        // Read RemoteAddresses for one rule under the policy lock, releasing the COM RCW
        // before returning. Yields a null string when the rule does not exist.
        private static string ReadRemoteAddressesForRule(string ruleName)
        {
            INetFwRule rule = null;
            try
            {
                lock (policyLock)
                {
                    try
                    {
                        rule = policy.Rules.Item(ruleName);
                    }
                    catch
                    {
                        return null; // does not exist
                    }
                    if (rule is null)
                    {
                        return null;
                    }
                    return rule.RemoteAddresses ?? string.Empty;
                }
            }
            finally
            {
                ReleaseRule(rule);
            }
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses(string ruleNamePrefix = null)
        {
            string prefix = (ruleNamePrefix is null ? BlockRulePrefix : ruleNamePrefix);
            for (int i = 0; ; i += MaxIpAddressesPerRule)
            {
                string ruleName = prefix + i.ToString(CultureInfo.InvariantCulture);
                string remoteAddresses = ReadRemoteAddressesForRule(ruleName);
                if (remoteAddresses is null)
                {
                    yield break;
                }
                foreach (string ip in remoteAddresses.Split(','))
                {
                    int pos = ip.IndexOfAny(firewallEntryDelimiters);
                    yield return pos < 0 ? ip : ip[..pos];
                }
            }
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses(string ruleNamePrefix = null)
        {
            string prefix = (ruleNamePrefix is null ? AllowRulePrefix : ruleNamePrefix);

            for (int i = 0; ; i += MaxIpAddressesPerRule)
            {
                string ruleName = prefix + i.ToString(CultureInfo.InvariantCulture);
                string remoteAddresses = ReadRemoteAddressesForRule(ruleName);
                if (remoteAddresses is null)
                {
                    yield break;
                }
                foreach (string ip in remoteAddresses.Split(','))
                {
                    int pos = ip.IndexOfAny(firewallEntryDelimiters);
                    yield return pos < 0 ? ip : ip[..pos];
                }
            }
        }

        /// <inheritdoc />
        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            string prefix = (string.IsNullOrWhiteSpace(ruleNamePrefix) ? RulePrefix : RulePrefix + ruleNamePrefix);

            // Snapshot the RemoteAddresses strings while the RuleList is still live, then dispose
            // the rules and yield from managed memory. Yielding from inside the using block would
            // either keep COM RCWs alive across the consumer's iteration (which may be slow or
            // unbounded) or, worse, dispose them while the consumer is still reading.
            List<string> ipLists = [];
            using (var matchedRules = EnumerateRulesMatchingPrefix(prefix))
            {
                foreach (INetFwRule rule in matchedRules)
                {
                    string ipList = rule.RemoteAddresses;
                    if (!string.IsNullOrWhiteSpace(ipList) && ipList != "*")
                    {
                        ipLists.Add(ipList);
                    }
                }
            }

            foreach (string ipList in ipLists)
            {
                foreach (string ip in ipList.Split(','))
                {
                    if (IPAddressRange.TryParse(ip, out IPAddressRange range))
                    {
                        yield return range;
                    }
                    // else // should never happen
                }
            }
        }

        /// <inheritdoc />
        public override string GetPorts(string ruleName)
        {
            INetFwRule rule = null;
            try
            {
                lock (policyLock)
                {
                    rule = policy.Rules.Item(ruleName);
                    return rule.LocalPorts ?? string.Empty;
                }
            }
            catch
            {
                // not exist, no way to determine this without throwing
            }
            finally
            {
                ReleaseRule(rule);
            }
            return null;
        }

        /// <inheritdoc />
        public override void Truncate()
        {
            using var matchedRules = EnumerateRulesMatchingPrefix(RulePrefix);
            foreach (INetFwRule rule in matchedRules)
            {
                lock (policyLock)
                {
                    try
                    {
                        policy.Rules.Remove(rule.Name);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Enable local subnet traffic for windows firewall
        /// </summary>
        public void EnableLocalSubnetTrafficViaFirewall()
        {
            string ruleName = RulePrefix + "AllowLocalTraffic";
            string localIP = DefaultDnsLookup.GetLocalIPAddress().ToString();
            if (localIP != null)
            {
                Match m = Regex.Match(localIP, "\\.[0-9]+$");
                if (m.Success)
                {
                    string remoteIPAddresses = localIP[..m.Index] + ".0/24";
                    GetOrCreateRule(ruleName, remoteIPAddresses, NetFwAction.Allow);
                }
            }
        }
    }
}
