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

using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Linux firewall using firewalld.
    /// This class also works on Windows but only modifies files, does not actually use the firewall.
    /// </summary>
    [RequiredOperatingSystem(OSUtility.Linux, Priority = 5, FallbackFirewallType = typeof(IPBanLinuxFirewallIPTables))]
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public class IPBanLinuxFirewallD : IPBanBaseFirewall
    {
        private const int allowPriority = 10;
        private const int dropPriority = 20;

        private readonly string zoneFileOrig;
        private readonly string zoneFile;
        private readonly string allowRuleName;
        private readonly string allowRuleName6;

        private bool dirty;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix</param>
        public IPBanLinuxFirewallD(string rulePrefix = null) : base(rulePrefix)
        {
            if (OSUtility.IsLinux)
            {
                zoneFileOrig = "/usr/lib/firewalld/zones/public.xml";
                zoneFile = "/etc/firewalld/zones/public.xml";
    }
            else
            {
                // windows virtual layer
                zoneFileOrig = Path.Combine(AppContext.BaseDirectory, "firewalld", "orig");
                zoneFile = Path.Combine(AppContext.BaseDirectory, "firewalld", "override");
                Directory.CreateDirectory(zoneFileOrig);
                Directory.CreateDirectory(zoneFile);
                zoneFileOrig = Path.Combine(zoneFileOrig, "public.xml");
                zoneFile = Path.Combine(zoneFile, "public.xml");
            }
            allowRuleName = AllowRulePrefix + "4";
            allowRuleName = AllowRulePrefix + "6";
            EnsureZoneFile();
        }

        /// <inheritdoc />
        public override Task Update(CancellationToken cancelToken = default)
        {
            if (dirty && OSUtility.IsLinux)
            {
                IPBanLinuxBaseFirewallIPTables.RunProcess("firewall-cmd", true, "--reload");
            }
            dirty = false;
            return base.Update(cancelToken);
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
            var set4 = set + "4";
            var set6 = set + "6";
            var ip4s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var ip6s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            var result = IPBanLinuxIPSetFirewallD.UpsertSet(set4, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ip4s, cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s, cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(false, allowPriority, set4, set6, allowedPorts);

            // done
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // create or update sets
            string set = string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix;
            var set4 = set + "4";
            var set6 = set + "6";
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
            var set4 = set + "4";
            var set6 = set + "6";
            var ip4s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var ip6s = ipAddresses.Where(i => i.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            var result = IPBanLinuxIPSetFirewallD.UpsertSet(set4, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ip4s, cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s, cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(true, dropPriority, set4, set6, allowedPorts);

            // done
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            // create or update sets
            string set = string.IsNullOrWhiteSpace(ruleNamePrefix) ? BlockRulePrefix : RulePrefix + ruleNamePrefix;
            var set4 = set + "4";
            var set6 = set + "6";
            var result = IPBanLinuxIPSetFirewallD.UpsertSetDelta(set4, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV4,
                ipAddresses.Where(i => i.IsIPV4), cancelToken);
            result |= IPBanLinuxIPSetFirewallD.UpsertSetDelta(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ipAddresses.Where(i => !i.IsIPV4), cancelToken);

            // create or update rule
            result |= CreateOrUpdateRule(true, dropPriority, set4, set6, allowedPorts);

            // done
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public override bool DeleteRule(string ruleName)
        {
            var result = IPBanLinuxIPSetFirewallD.DeleteSet(ruleName);
            result |= DeleteRuleInternal(ruleName);
            dirty = true;
            return result;
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            var ruleTypes = GetRuleTypes();
            var ruleNames = GetRuleNames(RulePrefix);
            foreach (var rule in ruleNames.Where(r => ruleTypes.TryGetValue(r, out var accept) && accept))
            {
                var entries = IPBanLinuxIPSetFirewallD.ReadSet(rule);
                foreach (var entry in entries)
                {
                    yield return entry;
                }
            }
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            var ruleTypes = GetRuleTypes();
            var ruleNames = GetRuleNames(RulePrefix);
            foreach (var rule in ruleNames.Where(r => ruleTypes.TryGetValue(r, out var accept) && !accept))
            {
                var entries = IPBanLinuxIPSetFirewallD.ReadSet(rule);
                foreach (var entry in entries)
                {
                    yield return entry;
                }
            }
        }

        /// <inheritdoc />
        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            if (!string.IsNullOrWhiteSpace(ruleNamePrefix) && !ruleNamePrefix.StartsWith(RulePrefix))
            {
                ruleNamePrefix = RulePrefix + ruleNamePrefix;
            }
            var ruleNames = GetRuleNames(ruleNamePrefix);
            foreach (var rule in ruleNames)
            {
                var entries = IPBanLinuxIPSetFirewallD.ReadSet(rule);
                foreach (var entry in entries)
                {
                    yield return entry;
                }
            }
        }

        /// <inheritdoc />
        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            var rules = IPBanLinuxIPSetFirewallD.GetSetNames(ruleNamePrefix ?? RulePrefix);
            return rules;
        }

        /// <inheritdoc />
        public override bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            if (System.Net.IPAddress.TryParse(ipAddress, out var ipObj))
            {
                foreach (var ip in EnumerateAllowedIPAddresses())
                {
                    if (IPAddressRange.TryParse(ip, out var range) && range.Contains(ipObj))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <inheritdoc />
        public override bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            if (System.Net.IPAddress.TryParse(ipAddress, out var ipObj))
            {
                var ruleTypes = GetRuleTypes();
                foreach (var kv in ruleTypes.Where(r => !r.Value))
                {
                    foreach (var ip in IPBanLinuxIPSetFirewallD.ReadSet(kv.Key))
                    {
                        if (IPAddressRange.TryParse(ip, out var range) && range.Contains(ipObj))
                        {
                            ruleName = kv.Key;
                            return true;
                        }
                    }
                }
            }
            ruleName = null;
            return false;
        }

        /// <inheritdoc />
        public override void Truncate()
        {
            EnsureZoneFile();
            var setNames = IPBanLinuxIPSetFirewallD.GetSetNames(RulePrefix);
            foreach (var ruleName in setNames)
            {
                DeleteRule(ruleName);
            }
            dirty = true;
        }

        private bool CreateOrUpdateRule(bool drop, int priority, string ruleIP4, string ruleIP6, IEnumerable<PortRange> allowedPorts)
        {
            EnsureZoneFile();

            // load zone from file
            XmlDocument doc = new();
            doc.Load(zoneFile);

            // grab rule for ip4 and ip6
            if (doc.SelectSingleNode($"//rule/source[@ipset='{ruleIP4}']") is not XmlElement ruleElement4)
            {
                ruleElement4 = doc.CreateElement("rule");
                doc.DocumentElement.AppendChild(ruleElement4);
            }
            else
            {
                // go from source to rule element
                ruleElement4 = ruleElement4.ParentNode as XmlElement;
                ruleElement4.IsEmpty = true;
                ruleElement4.IsEmpty = false;
            }
            if (doc.SelectSingleNode($"//rule/source[@ipset='{ruleIP6}']") is not XmlElement ruleElement6)
            {
                ruleElement6 = doc.CreateElement("rule");
                doc.DocumentElement.AppendChild(ruleElement6);
            }
            else
            {
                // go from source to rule element
                ruleElement6 = ruleElement6.ParentNode as XmlElement;
                ruleElement6.IsEmpty = true;
                ruleElement6.IsEmpty = false;
            }

            // assign rule attributes
            var action = drop ? "drop" : "accept";
            var priorityString = priority.ToString();
            ruleElement4.SetAttribute("priority", priorityString);
            ruleElement6.SetAttribute("priority", priorityString);

            // create and add source element
            var source4 = doc.CreateElement("source");
            source4.SetAttribute("ipset", ruleIP4);
            var source6 = doc.CreateElement("source");
            source6.SetAttribute("ipset", ruleIP6);
            ruleElement4.AppendChild(source4);
            ruleElement6.AppendChild(source6);

            // create and add port elements for each port entry
            var ports = allowedPorts;
            if (drop)
            {
                ports = IPBanFirewallUtility.GetBlockPortRanges(ports);
            }
            if (ports is not null)
            {
                foreach (var port in ports)
                {
                    var port4 = doc.CreateElement("port");
                    port4.SetAttribute("port", port.ToString());
                    port4.SetAttribute("protocol", "tcp");
                    var port6 = doc.CreateElement("port");
                    port6.SetAttribute("port", port.ToString());
                    port6.SetAttribute("protocol", "tcp");
                    ruleElement4.AppendChild(port4);
                    ruleElement6.AppendChild(port6);
                }
            }

            // create and add either drop or accept element
            if (drop)
            {
                var drop4 = doc.CreateElement("drop");
                var drop6 = doc.CreateElement("drop");
                ruleElement4.AppendChild(drop4);
                ruleElement6.AppendChild(drop6);
            }
            else
            {
                var accept4 = doc.CreateElement("accept");
                var accept6 = doc.CreateElement("accept");
                ruleElement4.AppendChild(accept4);
                ruleElement6.AppendChild(accept6);
            }

            // make sure forward node is at the end
            var forwardNode = doc.DocumentElement.SelectSingleNode("/forward");
            if (forwardNode is XmlElement forwardElement)
            {
                forwardNode.ParentNode.RemoveChild(forwardElement);
                doc.DocumentElement.AppendChild(forwardElement);
            }

            // pretty print
            XDocument xDoc = XDocument.Parse(doc.OuterXml);
            var xml = xDoc.ToString();

            // write the zone file back out and reload the firewall
            ExtensionMethods.Retry(() => File.WriteAllText(zoneFile, xml, ExtensionMethods.Utf8EncodingNoPrefix));
            dirty = true;
            return true;
        }

        private bool DeleteRuleInternal(string ruleName)
        {
            bool foundOne = false;

            if (!File.Exists(zoneFile))
            {
                return foundOne;
            }

            XmlDocument doc = new();
            doc.Load(zoneFile);
            var xmlElement = doc.SelectSingleNode($"//rule/source[@ipset='{ruleName}']");
            if (xmlElement is not null)
            {
                // remove the rule element which is the source parent
                xmlElement.ParentNode.ParentNode.RemoveChild(xmlElement.ParentNode);
                File.WriteAllText(zoneFile, doc.OuterXml, ExtensionMethods.Utf8EncodingNoPrefix);
                foundOne = true;
            }
            return foundOne;
        }

        private IReadOnlyDictionary<string, bool> GetRuleTypes()
        {
            Dictionary<string, bool> rules = new();
            var setNames = IPBanLinuxIPSetFirewallD.GetSetNames(RulePrefix);
            if (File.Exists(zoneFile))
            {
                XmlDocument doc = new();
                doc.Load(zoneFile);
                var xmlRules = doc.SelectNodes($"//rule");
                if (xmlRules is not null)
                {
                    foreach (var node in xmlRules)
                    {
                        if (node is XmlElement xmlElement)
                        {
                            var sourceNode = xmlElement.SelectSingleNode("source");
                            if (sourceNode is XmlElement sourceElement)
                            {
                                var ipsetName = sourceElement.Attributes["ipset"]?.Value;
                                if (!string.IsNullOrWhiteSpace(ipsetName) &&
                                    setNames.Contains(ipsetName))
                                {
                                    var acceptNode = xmlElement.SelectSingleNode("accept");
                                    rules[ipsetName] = acceptNode is not null;
                                }
                            }

                        }
                    }
                }
            }
            return rules;
        }

        private void EnsureZoneFile()
        {
            const string fallbackZoneFileContents = "<?xml version=\"1.0\" encoding=\"utf-8\"?><zone><short>Public</short><description>For use in public areas. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.</description><service name=\"ssh\"/><service name=\"dhcpv6-client\"/><forward/></zone>";
            if (!File.Exists(zoneFile))
            {
                string origZoneFileContents;
                if (!File.Exists(zoneFileOrig))
                {
                    origZoneFileContents = fallbackZoneFileContents;
                }
                else
                {
                    origZoneFileContents = File.ReadAllText(zoneFileOrig, ExtensionMethods.Utf8EncodingNoPrefix);
                }
                File.WriteAllText(zoneFile, origZoneFileContents, ExtensionMethods.Utf8EncodingNoPrefix);
            }
        }
    }
}
