#region Imports

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

using NetFwTypeLib;

#endregion Imports

namespace IPBan
{
    /// <summary>
    /// Helper class for Windows Firewall (NetFwTypeLib). Must call Initialize first!
    /// </summary>
    public static class IPBanWindowsFirewall
    {
        private const string clsidFwPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        private const string clsidFwRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        private const int maxIpAddressesPerRule = 1000; // do not change!
        private static INetFwPolicy2 policy;

        public static string RulePrefix { get; private set; }

        /// <summary>
        /// Initialize - call this from the main thread to avoid COM issues
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public static void Initialize(string rulePrefix)
        {
            Type objectType = Type.GetTypeFromCLSID(new Guid(clsidFwPolicy2));
            policy = Activator.CreateInstance(objectType) as INetFwPolicy2;
            RulePrefix = (string.IsNullOrWhiteSpace(rulePrefix) ? "IPBan_BlockIPAddresses_" : rulePrefix);
        }

        private static string CreateRuleStringForIPAddresses(string[] ipAddresses, int index, int count)
        {
            if (count == 0 || index >= ipAddresses.Length)
            {
                return string.Empty;
            }

            // don't overrun array
            count = Math.Min(count, ipAddresses.Length - index);

            StringBuilder b = new StringBuilder(count * 16);
            b.Append(ipAddresses[index]);
            for (int i = index + 1; i < index + count; i++)
            {
                b.Append(',');
                b.Append(ipAddresses[i]);
            }

            return b.ToString();
        }

        private static void CreateRule(string[] ipAddresses, int index, int count)
        {
            Type type = Type.GetTypeFromCLSID(new Guid(clsidFwRule));
            string ruleName = RulePrefix + index;
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
                rule = Activator.CreateInstance(type) as INetFwRule;
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

        /// <summary>
        /// Creates new rules to block all the ip addresses, and removes any left-over rules. Exceptions are logged.
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <returns>True if success, false if error</returns>
        public static bool CreateRules(string[] ipAddresses)
        {
            try
            {
                int i;
                for (i = 0; i < ipAddresses.Length; i += maxIpAddressesPerRule)
                {
                    CreateRule(ipAddresses, i, maxIpAddressesPerRule);
                }
                DeleteRules(i);
                return true;
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, ex.ToString());
                return false;
            }
        }

        /// <summary>
        /// Delete all rules with a name beginning with the rule prefix. Exceptions are logged.
        /// </summary>
        /// <param name="startIndex">The start index to begin deleting rules at. The index is appended to the rule prefix.</param>
        /// <returns>True if success, false if error</returns>
        public static bool DeleteRules(int startIndex = 0)
        {
            try
            {
                List<INetFwRule> toDelete = new List<INetFwRule>();
                foreach (INetFwRule rule in policy.Rules)
                {
                    if (rule.Name.StartsWith(RulePrefix))
                    {
                        int index = int.Parse(rule.Name.Substring(RulePrefix.Length));
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
                return true;
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, ex.ToString());
                return false;
            }
        }
    }
}
