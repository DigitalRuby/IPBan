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
    [RequiredOperatingSystem(IPBanOperatingSystem.Windows)]
    public class IPBanWindowsFirewall : IIPBanFirewall
    {
        private const string clsidFwPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        private const string clsidFwRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        private const int maxIpAddressesPerRule = 1000; // do not change!
        private static readonly INetFwPolicy2 policy = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid(clsidFwPolicy2))) as INetFwPolicy2;
        private static readonly Type ruleType = Type.GetTypeFromCLSID(new Guid(clsidFwRule));

        private string CreateRuleStringForIPAddresses(IReadOnlyList<string> ipAddresses, int index, int count)
        {
            if (count == 0 || index >= ipAddresses.Count)
            {
                return string.Empty;
            }

            // don't overrun array
            count = Math.Min(count, ipAddresses.Count - index);

            StringBuilder b = new StringBuilder(count * 16);
            foreach (string ipAddress in ipAddresses)
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

        private INetFwRule GetOrCreateRule(string ruleName, string remoteIPAddresses, NET_FW_ACTION_ action)
        {
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
                    policy.Rules.Add(rule);
                }
                try
                {
                    rule.RemoteAddresses = remoteIPAddresses;
                }
                catch
                {
                    if (action == NET_FW_ACTION_.NET_FW_ACTION_ALLOW)
                    {
                        // if fail and we are allowing, remove the rule, else this rule will allow all ip
                        policy.Rules.Remove(ruleName);
                    }
                }
                return rule;
            }
        }

        private void CreateBlockRule(IReadOnlyList<string> ipAddresses, int index, int count)
        {
            string ruleName = RulePrefix + index.ToString(CultureInfo.InvariantCulture);
            string remoteIpString = CreateRuleStringForIPAddresses(ipAddresses, index, count);
            GetOrCreateRule(ruleName, remoteIpString, NET_FW_ACTION_.NET_FW_ACTION_BLOCK);
        }

        public string RulePrefix { get; private set; } = "IPBan_BlockIPAddresses_";

        public void Initialize(string rulePrefix)
        {
            RulePrefix = rulePrefix;
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
                DeleteRules(i);
                return true;
            }
            catch (Exception ex)
            {
                Log.Exception(ex);
                return false;
            }
        }

        public bool AllowIPAddresses(IReadOnlyList<string> ipAddresses)
        {
            string remoteIP = CreateRuleStringForIPAddresses(ipAddresses, 0, ipAddresses.Count);
            INetFwRule rule = GetOrCreateRule(RulePrefix + "AllowIPAddresses", remoteIP, NET_FW_ACTION_.NET_FW_ACTION_ALLOW);
            return (rule != null);
        }

        public bool DeleteRules(int startIndex = 0)
        {
            try
            {
                lock (policy)
                {
                    for (int i = startIndex; ; i += maxIpAddressesPerRule)
                    {
                        string ruleName = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
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
                Log.Exception(ex);
                return false;
            }
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
                Log.Exception(ex);
            }
            return false;
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            try
            {
                lock (policy)
                {
                    string ruleName = RulePrefix + "AllowIPAddresses";
                    try
                    {
                        INetFwRule rule = policy.Rules.Item(ruleName);
                        return (rule != null && rule.RemoteAddresses.Contains(ipAddress));
                    }
                    catch
                    {
                        // OK, rule does not exist
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex);
            }
            return false;
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            int i = 0;
            while (true)
            {
                string ruleName = RulePrefix + i.ToString(CultureInfo.InvariantCulture);
                INetFwRule rule = null;
                try
                {
                    rule = policy.Rules.Item(ruleName);
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
                i++;
            }
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            string ruleName = RulePrefix + "AllowIPAddresses";
            INetFwRule rule;
            try
            {
                rule = policy.Rules.Item(ruleName);
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

        public string GetLocalIPAddress()
        {
            try
            {
                IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (IPAddress ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.MapToIPv4().ToString();
                    }
                }
            }
            catch
            {

            }
            return null;
        }

        public void EnableLocalSubnetTrafficViaFirewall()
        {
            string ruleName = RulePrefix + "AllowLocalTraffic";
            string localIP = GetLocalIPAddress();
            if (localIP != null)
            {
                Match m = Regex.Match(localIP, "\\.[0-9]+$");
                if (m.Success)
                {
                    string remoteIPAddresses = localIP.Substring(0, m.Index) + ".0/24";
                    INetFwRule rule = GetOrCreateRule(ruleName, remoteIPAddresses, NET_FW_ACTION_.NET_FW_ACTION_ALLOW);
                }
            }
        }
    }
}
