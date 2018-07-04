#region Imports

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

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
            b.Append(ipAddresses[index]);
            for (int i = index + 1; i < index + count; i++)
            {
                b.Append(',');
                b.Append(ipAddresses[i]);
            }

            return b.ToString();
        }

        private void CreateRule(IReadOnlyList<string> ipAddresses, int index, int count)
        {
            lock (policy)
            {
                string ruleName = RulePrefix + index.ToString(CultureInfo.InvariantCulture);
                string remoteIpString = CreateRuleStringForIPAddresses(ipAddresses, index, count);
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
                    rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                    rule.Description = "Automatically created by IPBan";
                    rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                    rule.EdgeTraversal = false;
                    rule.Grouping = "IPBan";
                    rule.LocalAddresses = "*";
                    rule.Profiles = int.MaxValue; // all
                    rule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                    policy.Rules.Add(rule);
                }
                rule.RemoteAddresses = remoteIpString;
            }
        }

        public string RulePrefix { get; private set; } = "IPBan_BlockIPAddresses_";

        /// <summary>
        /// Initialize
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public void Initialize(string rulePrefix)
        {
            RulePrefix = rulePrefix;
        }

        /// <summary>
        /// Creates new rules to block all the ip addresses, and removes any left-over rules. Exceptions are logged.
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <returns>True if success, false if error</returns>
        public bool CreateRules(IReadOnlyList<string> ipAddresses)
        {
            try
            {
                int i;
                for (i = 0; i < ipAddresses.Count; i += maxIpAddressesPerRule)
                {
                    CreateRule(ipAddresses, i, maxIpAddressesPerRule);
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

        /// <summary>
        /// Delete all rules with a name beginning with the rule prefix. Exceptions are logged.
        /// </summary>
        /// <param name="startIndex">The start index to begin deleting rules at. The index is appended to the rule prefix.</param>
        /// <returns>True if success, false if error</returns>
        public bool DeleteRules(int startIndex = 0)
        {
            try
            {
                lock (policy)
                {
                    List<INetFwRule> toDelete = new List<INetFwRule>();
                    foreach (INetFwRule rule in policy.Rules)
                    {
                        if (rule.Name.StartsWith(RulePrefix))
                        {
                            int index = int.Parse(rule.Name.Substring(RulePrefix.Length), CultureInfo.InvariantCulture);
                            if (index >= startIndex)
                            {
                                rule.Enabled = false;
                                toDelete.Add(rule);
                            }
                        }
                    }
                    foreach (INetFwRule rule in toDelete)
                    {
                        policy.Rules.Remove(rule.Name);
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

        /// <summary>
        /// Checks if an ip address is blocked in the firewall
        /// </summary>
        /// <param name="ipAddress">IPAddress</param>
        /// <returns>True if the ip address is blocked in the firewall, false otherwise</returns>
        public bool IsIPAddressBlocked(string ipAddress)
        {
            try
            {
                lock (policy)
                {
                    foreach (INetFwRule rule in policy.Rules)
                    {
                        if (rule.Name.StartsWith(RulePrefix) && rule.RemoteAddresses.Contains(ipAddress))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex);
                return false;
            }
            return false;
        }

        /// <summary>
        /// Loop through all banned ip addresses
        /// </summary>
        /// <returns>IEnumerable of all ip addresses</returns>
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
    }
}
