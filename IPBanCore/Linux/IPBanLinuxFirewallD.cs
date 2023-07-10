using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

using DigitalRuby.IPBanCore;

namespace DigitalRuby.IPBanProShared
{
    /// <summary>
    /// Linux firewall using firewalld.
    /// </summary>
    [RequiredOperatingSystem(OSUtility.Linux, Priority = 5, FallbackFirewallType = typeof(IPBanLinuxFirewallIPTables))]
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public class IPBanLinuxFirewallD : IPBanBaseFirewall
    {
        private const string zoneFile = "/etc/firewalld/zones/public.xml";
        private const int allowPriority = 10;
        private const int dropPriority = 20;

        private readonly string allowRuleName;
        private readonly string allowRuleName6;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public IPBanLinuxFirewallD(string rulePrefix) : base(rulePrefix)
        {
            var pm = OSUtility.UsesYumPackageManager ? "yum" : "apt";
            int exitCode = IPBanLinuxBaseFirewallIPTables.RunProcess(pm, true, "install -q -y firewalld && systemctl start firewalld && systemctl enable firewalld");
            if (exitCode != 0)
            {
                throw new System.IO.IOException("Failed to initialize firewalld with code: " + exitCode);
            }
            IPBanLinuxBaseFirewallIPTables.RunProcess("ufw", false, "disable");
            allowRuleName = AllowRulePrefix + "0_4";
            allowRuleName = AllowRulePrefix + "0_6";
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            // create or update sets
            var ranges = ipAddresses.Select(i => IPAddressRange.Parse(i));
            var ip4s = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var ip6s = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            var result = IPBanLinuxIPSetFirewallD.UpsertSet(allowRuleName, IPBanLinuxIPSetIPTables.HashTypeSingleIP, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ip4s, cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(allowRuleName6, IPBanLinuxIPSetIPTables.HashTypeSingleIP, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s, cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(false, allowPriority, allowRuleName, allowRuleName6, Array.Empty<PortRange>());

            // done
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // create or update sets
            string set = string.IsNullOrWhiteSpace(ruleNamePrefix) ? AllowRulePrefix : RulePrefix + ruleNamePrefix;
            var set4 = set + "_4";
            var set6 = set + "_6";
            var ip4s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var ip6s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            var result = IPBanLinuxIPSetFirewallD.UpsertSet(set4, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ip4s, cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s, cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(false, allowPriority, set4, set6, allowedPorts);

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // create or update sets
            string set = string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix;
            var set4 = set + "_4";
            var set6 = set + "_6";
            var ranges = ipAddresses.Select(i => IPAddressRange.Parse(i));
            var ip4s = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var ip6s = ranges.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            var result = IPBanLinuxIPSetFirewallD.UpsertSet(set4, IPBanLinuxIPSetIPTables.HashTypeSingleIP, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ip4s, cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeSingleIP, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s, cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(true, dropPriority, set4, set6, allowedPorts);

            // done
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // create or update sets
            string set = string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix;
            var set4 = set + "_4";
            var set6 = set + "_6";
            var ip4s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var ip6s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            var result = IPBanLinuxIPSetFirewallD.UpsertSet(set4, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ip4s, cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s, cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(true, dropPriority, set4, set6, allowedPorts);

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // create or update sets
            string set = string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix;
            var set4 = set + "_4";
            var set6 = set + "_6";
            var result = IPBanLinuxIPSetFirewallD.UpsertSetDelta(set4, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ipAddresses.Where(i => i.IsIPV4), cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSetDelta(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ipAddresses.Where(i => !i.IsIPV4), cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(true, dropPriority, set4, set6, allowedPorts);

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override bool DeleteRule(string ruleName)
        {
            var result = IPBanLinuxIPSetFirewallD.DeleteSet(ruleName);
            result |= DeleteRuleInternal(ruleName);
            ReloadFirewallD();
            return result;
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override void Truncate()
        {
            foreach (var ruleName in IPBanLinuxIPSetFirewallD.GetSetNames(RulePrefix))
            {
                IPBanLinuxIPSetFirewallD.DeleteSet(ruleName);
                DeleteRuleInternal(ruleName);
            }
            ReloadFirewallD();
        }

        private static bool CreateOrUpdateRule(bool drop, int priority, string ruleIP4, string ruleIP6, IEnumerable<PortRange> allowedPorts)
        {
            var action = drop ? "drop" : "accept";
            StringBuilder command = new(1024);

            // create rule commands
            var ruleText = $"rule source ipset={ruleIP4} {action} priority={priority}";
            command.Append($"if firewall-cmd --permanent --zone=public--query-rich-rule=\"{ruleText}\"; then firewall-cmd --remove-rich-rule=\"{ruleText}\"; fi; ");
            command.Append($"firewall-cmd --permanent --zone=public --add-rich-rule=\"{ruleText}\"; ");
            ruleText = $"rule source ipset={ruleIP6} {action} priority={priority}";
            command.Append($"if firewall-cmd --permanent --zone=public --query-rich-rule=\"{ruleText}\"; then firewall-cmd --remove-rich-rule=\"{ruleText}\"; fi; ");
            command.Append($"firewall-cmd --permanent --zone=public --add-rich-rule=\"{ruleText}\"; ");
            command.Append("firewall-cmd --reload");
            return IPBanLinuxBaseFirewallIPTables.RunProcess(string.Empty, true, command.ToString()) == 0;
        }

        private static bool ReloadFirewallD()
        {
            return IPBanLinuxBaseFirewallIPTables.RunProcess("firewall-cmd", true, "--reload") == 0;
        }

        private static bool DeleteRuleInternal(string ruleName)
        {
            bool foundOne = false;

            if (!File.Exists(zoneFile))
            {
                return foundOne;
            }

            XmlDocument doc = new();
            doc.LoadXml(zoneFile);
            var rules = doc.SelectNodes($"//rule/source[@ipset='{ruleName}']");
            if (rules is not null)
            {
                foreach (var rule in rules)
                {
                    if (rule is XmlElement xmlElement)
                    {
                        // remove the rule element which is the source parent
                        xmlElement.ParentNode.ParentNode.RemoveChild(xmlElement.ParentNode);
                        foundOne = true;
                    }
                }
            }
            if (foundOne)
            {
                File.WriteAllText(zoneFile, doc.OuterXml, ExtensionMethods.Utf8EncodingNoPrefix);
            }
            return foundOne;
        }
    }
}
