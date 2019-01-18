#region Imports

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using NetFwTypeLib;

#endregion Imports

namespace IPBan
{
    /// <summary>
    /// Helper class for Windows firewall and banning ip addresses.
    /// </summary>
    [RequiredOperatingSystem(IPBanOS.Windows)]
    public class IPBanWindowsFirewall : IIPBanFirewall
    {
        // DO NOT CHANGE THESE CONST AND READONLY FIELDS!
        private const int maxIpAddressesPerRule = 1000;
        private const string clsidFwPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        private const string clsidFwRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        private static readonly INetFwPolicy2 policy = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid(clsidFwPolicy2))) as INetFwPolicy2;
        private static readonly Type ruleType = Type.GetTypeFromCLSID(new Guid(clsidFwRule));

        private string allowRulePrefix;

        private string CreateRuleStringForIPAddresses(IReadOnlyList<string> ipAddresses, int index, int count)
        {
            if (count == 0 || index >= ipAddresses.Count)
            {
                return string.Empty;
            }

            // don't overrun array
            count = Math.Min(count, ipAddresses.Count - index);

            StringBuilder b = new StringBuilder(count * 16);
            foreach (string ipAddress in ipAddresses.Skip(index).Take(count))
            {
                if (ipAddress.TryGetFirewallIPAddress(out string firewallIPAddress))
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

        private bool GetOrCreateRule(string ruleName, string remoteIPAddresses, NET_FW_ACTION_ action, params PortRange[] allowedPorts)
        {
            remoteIPAddresses = (remoteIPAddresses ?? string.Empty).Trim();
            bool emptyIPAddressString = string.IsNullOrWhiteSpace(remoteIPAddresses) || remoteIPAddresses == "*";
            bool ruleNeedsToBeAdded = false;

            lock (policy)
            {
                INetFwRule rule = null;
                try
                {
                    rule = policy.Rules.Item(ruleName);
                }
                catch
                {
                    // ignore exception, assume does not exist
                }
                if (rule == null)
                {
                    rule = Activator.CreateInstance(ruleType) as INetFwRule;
                    rule.Name = ruleName;
                    rule.Enabled = true;
                    rule.Action = action;
                    rule.Description = "Automatically created by IPBan";
                    rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                    rule.EdgeTraversal = false;
                    rule.Grouping = "IPBan";
                    rule.LocalAddresses = "*";
                    rule.Profiles = int.MaxValue; // all
                    rule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                    if (allowedPorts != null && allowedPorts.Length != 0)
                    {
                        if (action == NET_FW_ACTION_.NET_FW_ACTION_BLOCK)
                        {
                            rule.LocalPorts = IPBanFirewallUtility.GetPortRangeStringBlockExcept(allowedPorts);
                        }
                        else
                        {
                            rule.LocalPorts = IPBanFirewallUtility.GetPortRangeStringAllow(allowedPorts);
                        }
                    }
                    ruleNeedsToBeAdded = true;
                }

                // do not ever set an empty string, Windows treats this as * which means everything
                if (!emptyIPAddressString)
                {
                    try
                    {
                        rule.RemoteAddresses = remoteIPAddresses;
                    }
                    catch
                    {
                    }
                }

                if (emptyIPAddressString || string.IsNullOrWhiteSpace(rule.RemoteAddresses) || rule.RemoteAddresses == "*")
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
                return (rule != null);
            }
        }

        private void CreateBlockRule(IReadOnlyList<string> ipAddresses, int index, int count)
        {
            string ruleName = RulePrefix + index.ToString(CultureInfo.InvariantCulture);
            string remoteIpString = CreateRuleStringForIPAddresses(ipAddresses, index, count);
            GetOrCreateRule(ruleName, remoteIpString, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
        }

        private void MigrateOldDefaultRuleNames()
        {
            // migrate old default rule names to new names
            INetFwRule rule = null;
            for (int i = 0; ; i += maxIpAddressesPerRule)
            {
                lock (policy)
                {
                    try
                    {
                        rule = policy.Rules.Item("IPBan_BlockIPAddresses_" + i.ToString(CultureInfo.InvariantCulture));
                        rule.Name = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
                    }
                    catch
                    {
                        // ignore exception, assume does not exist
                        break;
                    }
                }
            }
            lock (policy)
            {
                try
                {
                    rule = policy.Rules.Item("IPBan_BlockIPAddresses_AllowIPAddresses");
                    rule.Name = allowRulePrefix + "0";
                }
                catch
                {
                    // ignore exception, assume does not exist
                }
            }
        }

        private bool DeleteRules(string rulePrefix, int startIndex = 0)
        {
            try
            {
                lock (policy)
                {
                    for (int i = startIndex; ; i += maxIpAddressesPerRule)
                    {
                        string ruleName = rulePrefix + i.ToString(CultureInfo.InvariantCulture);
                        try
                        {
                            INetFwRule rule = policy.Rules.Item(ruleName);
                            if (rule == null)
                            {
                                break;
                            }
                            policy.Rules.Remove(ruleName);
                        }
                        catch
                        {
                            break;
                        }
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return false;
            }
        }

        public string RulePrefix { get; private set; } = "IPBan_";

        public void Initialize(string rulePrefix)
        {
            if (string.IsNullOrWhiteSpace(rulePrefix))
            {
                rulePrefix = "IPBan_";
            }
            RulePrefix = rulePrefix.Trim();
            allowRulePrefix = RulePrefix + "Allow_";
            MigrateOldDefaultRuleNames();
        }

        public bool BlockIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            try
            {
                int i;
                for (i = 0; i < ipAddresses.Count; i += maxIpAddressesPerRule)
                {
                    CreateBlockRule(ipAddresses, i, maxIpAddressesPerRule);
                }
                DeleteRules(RulePrefix, i);
                return true;
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
                string prefix = RulePrefix + ruleNamePrefix;

                // recreate rules
                int counter = 0;
                int index = 0;
                StringBuilder ipList = new StringBuilder();
                foreach (IPAddressRange range in ranges)
                {
                    ipList.Append(range.ToCidrString());
                    ipList.Append(',');
                    if (++counter == maxIpAddressesPerRule)
                    {
                        ipList.Length--; // remove ending comma
                        GetOrCreateRule(prefix + index.ToString(CultureInfo.InvariantCulture), ipList.ToString(), NET_FW_ACTION_.NET_FW_ACTION_BLOCK, allowedPorts);
                        counter = 0;
                        index += maxIpAddressesPerRule;
                        ipList.Clear();
                    }
                }

                // create rule for any leftover ip addresses
                if (ipList.Length > 1)
                {
                    ipList.Length--; // remove ending comma
                    GetOrCreateRule(prefix + index.ToString(CultureInfo.InvariantCulture), ipList.ToString(), NET_FW_ACTION_.NET_FW_ACTION_BLOCK, allowedPorts);
                    index += maxIpAddressesPerRule;
                }

                // delete any leftover rules
                DeleteRules(prefix, index);
                return true;
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                return false;
            }
        }

        public bool AllowIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            if (ipAddresses == null || ipAddresses.Count == 0)
            {
                return false;
            }

            int i = 0;
            for (i = 0; i < ipAddresses.Count; i += maxIpAddressesPerRule)
            {
                string remoteIP = CreateRuleStringForIPAddresses(ipAddresses, i, maxIpAddressesPerRule);
                if (string.IsNullOrWhiteSpace(remoteIP))
                {
                    break;
                }
                GetOrCreateRule(allowRulePrefix + i.ToString(CultureInfo.InvariantCulture), remoteIP, NET_FW_ACTION_.NET_FW_ACTION_ALLOW);
            }
            DeleteRules(allowRulePrefix, i);
            return true;
        }

        public bool IsIPAddressBlocked(string ipAddress)
        {
            try
            {
                lock (policy)
                {
                    for (int i = 0; ; i += maxIpAddressesPerRule)
                    {
                        string ruleName = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
                        try
                        {
                            INetFwRule rule = policy.Rules.Item(ruleName);
                            if (rule == null)
                            {
                                // no more rules to check
                                break;
                            }
                            else if (rule.RemoteAddresses.Contains(ipAddress))
                            {
                                return true;
                            }
                        }
                        catch
                        {
                            // no more rules to check
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }
            return false;
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            try
            {
                lock (policy)
                {
                    for (int i = 0; ; i += maxIpAddressesPerRule)
                    {
                        string ruleName = allowRulePrefix + i.ToString(CultureInfo.InvariantCulture);
                        try
                        {
                            INetFwRule rule = policy.Rules.Item(ruleName);
                            if (rule == null)
                            {
                                break;
                            }
                            else if (rule.RemoteAddresses.Contains(ipAddress))
                            {
                                return true;
                            }
                        }
                        catch
                        {
                            // OK, rule does not exist
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }
            return false;
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            int i = 0;
            INetFwRule rule;

            while (true)
            {
                string ruleName = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
                try
                {
                    rule = policy.Rules.Item(ruleName);
                    if (rule == null)
                    {
                        break;
                    }
                }
                catch
                {
                    // does not exist
                    break;
                }
                foreach (string ip in rule.RemoteAddresses.Split(','))
                {
                    int pos = ip.IndexOf('/');
                    if (pos < 0)
                    {
                        yield return ip;
                    }
                    else
                    {
                        yield return ip.Substring(0, pos);
                    }
                }
                i += maxIpAddressesPerRule;
            }
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            INetFwRule rule;
            for (int i = 0; ; i += maxIpAddressesPerRule)
            {
                try
                {
                    rule = policy.Rules.Item(allowRulePrefix + i.ToString(CultureInfo.InvariantCulture));
                    if (rule == null)
                    {
                        break;
                    }
                }
                catch
                {
                    // OK, rule does not exist
                    yield break;
                }
                foreach (string ip in rule.RemoteAddresses.Split(','))
                {
                    int pos = ip.IndexOf('/');
                    if (pos < 0)
                    {
                        yield return ip;
                    }
                    else
                    {
                        yield return ip.Substring(0, pos);
                    }
                }
            }
        }

        public void EnableLocalSubnetTrafficViaFirewall()
        {
            string ruleName = RulePrefix + "AllowLocalTraffic";
            string localIP = DefaultDnsLookup.GetLocalIPAddress().ToString();
            if (localIP != null)
            {
                Match m = Regex.Match(localIP, "\\.[0-9]+$");
                if (m.Success)
                {
                    string remoteIPAddresses = localIP.Substring(0, m.Index) + ".0/24";
                    GetOrCreateRule(ruleName, remoteIPAddresses, NET_FW_ACTION_.NET_FW_ACTION_ALLOW);
                }
            }
        }
    }
}
