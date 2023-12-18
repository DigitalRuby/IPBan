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
        private const int allowPriority = -20;
        private const int dropPriority = -10;
        private const string defaultFallbackZoneFileContents = "<?xml version=\"1.0\" encoding=\"utf-8\"?><zone><short>Public</short><description>For use in public areas. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.</description><service name=\"ssh\"/><service name=\"dhcpv6-client\"/><forward/></zone>";

        private readonly string zoneFileOrig;
        private readonly string zoneFile;
        private readonly string allowRuleName;
        private readonly string allowRuleName6;
        private readonly bool canUseForwardNode;
        private readonly string fallbackZoneFileContents = defaultFallbackZoneFileContents;

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
                string version = OSUtility.StartProcessAndWait("sudo", "firewall-cmd --version");
                version = (version?.Trim()) ?? string.Empty;
                Logger.Warn("FirewallD version: {0}", version);
                if (!Version.TryParse(version, out var versionObj))
                {
                    versionObj = new(1, 0, 0);
                }
                canUseForwardNode = versionObj.Major >= 1;
                if (!canUseForwardNode)
                {
                    fallbackZoneFileContents = fallbackZoneFileContents.Replace("<forward/>", string.Empty);
                }
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
            allowRuleName6 = AllowRulePrefix + "6";
            EnsureZoneFile(zoneFile, zoneFileOrig, fallbackZoneFileContents);
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
                ip4s);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(allowRuleName6, IPBanLinuxIPSetIPTables.HashTypeSingleIP, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s);

            // create or update rule
            result |= CreateOrUpdateRule(zoneFile, zoneFileOrig, false, allowPriority, allowRuleName, allowRuleName6,
                Array.Empty<PortRange>(), canUseForwardNode, fallbackZoneFileContents);
            dirty = true;

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
                ip4s);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s);

            // create or update rule
            result |= CreateOrUpdateRule(zoneFile, zoneFileOrig, false, allowPriority, set4, set6, allowedPorts, canUseForwardNode, fallbackZoneFileContents);
            dirty = true;

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
                ip4s);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeSingleIP, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s);

            // create or update rule
            result |= CreateOrUpdateRule(zoneFile, zoneFileOrig, true, dropPriority, set4, set6, allowedPorts, canUseForwardNode, fallbackZoneFileContents);
            dirty = true;

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
                ip4s);
            result |= IPBanLinuxIPSetFirewallD.UpsertSet(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ip6s);

            // create or update rule
            result |= CreateOrUpdateRule(zoneFile, zoneFileOrig, true, dropPriority, set4, set6, allowedPorts, canUseForwardNode, fallbackZoneFileContents);
            dirty = true;

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
                ipAddresses.Where(i => i.IsIPV4));
            result |= IPBanLinuxIPSetFirewallD.UpsertSetDelta(set6, IPBanLinuxIPSetIPTables.HashTypeNetwork, IPBanLinuxIPSetIPTables.INetFamilyIPV6,
                ipAddresses.Where(i => !i.IsIPV4));

            // create or update rule
            result |= CreateOrUpdateRule(zoneFile, zoneFileOrig, true, dropPriority, set4, set6, allowedPorts, canUseForwardNode, fallbackZoneFileContents);
            dirty = true;

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
            EnsureZoneFile(zoneFile, zoneFileOrig, fallbackZoneFileContents);
            var setNames = IPBanLinuxIPSetFirewallD.GetSetNames(RulePrefix);
            foreach (var ruleName in setNames)
            {
                DeleteRule(ruleName);
            }
            dirty = true;
        }

        /// <summary>
        /// Create or update a firewalld rule
        /// </summary>
        /// <param name="zoneFile">Zone file</param>
        /// <param name="zoneFileOrig">Original zone file</param>
        /// <param name="drop">True for a drop rule, false for an allow rule</param>
        /// <param name="priority">Priority</param>
        /// <param name="ruleIP4">IP4 rule name</param>
        /// <param name="ruleIP6">IP6 rule name</param>
        /// <param name="allowedPorts">Allowed ports</param>
        /// <param name="canUseForwardNode">Whether forward node is allowed</param>
        /// <param name="fallbackZoneFileContents">Fallback zone file contents</param>
        /// <returns></returns>
        public static bool CreateOrUpdateRule(string zoneFile, string zoneFileOrig, bool drop, int priority, string ruleIP4, string ruleIP6,
            IEnumerable<PortRange> allowedPorts, bool canUseForwardNode, string fallbackZoneFileContents)
        {
            EnsureZoneFile(zoneFile, zoneFileOrig, fallbackZoneFileContents);

            // load zone from file
            XmlDocument doc = new();
            doc.Load(zoneFile);

            static void UpsertXmlRule(XmlDocument doc, string ruleName, string family, bool drop, int priority, IEnumerable<PortRange> allowedPorts)
            {
                // grab existing rule, if any
                if (doc.SelectSingleNode($"//rule/source[@ipset='{ruleName}']") is not XmlElement ruleElement)
                {
                    // no rule found, make a new one
                    ruleElement = doc.CreateElement("rule");
                    if (drop)
                    {
                        // add to end
                        doc.DocumentElement.AppendChild(ruleElement);
                    }
                    else
                    {
                        // find first rule element and insert before
                        var existingRule = doc.SelectSingleNode("//rule");
                        if (existingRule is null)
                        {
                            doc.DocumentElement.AppendChild(ruleElement);
                        }
                        else
                        {
                            doc.DocumentElement.InsertBefore(ruleElement, existingRule);
                        }
                    }
                }
                else
                {
                    // use existing rule and empty it out
                    ruleElement = ruleElement.ParentNode as XmlElement;
                    ruleElement.IsEmpty = true;
                    ruleElement.IsEmpty = false;
                }

                ruleElement.SetAttribute("family", family);

                // assign rule attributes
                var action = drop ? "drop" : "accept";
                var priorityString = priority.ToString();
                ruleElement.SetAttribute("priority", priorityString);

                // create and add source element
                var source = doc.CreateElement("source");
                source.SetAttribute("ipset", ruleName);
                ruleElement.AppendChild(source);

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
                        var portElement = doc.CreateElement("port");
                        portElement.SetAttribute("port", port.ToString());
                        portElement.SetAttribute("protocol", "tcp");
                        ruleElement.AppendChild(portElement);
                    }
                }
                else
                {
                    var portElement = doc.CreateElement("port");
                    portElement.SetAttribute("port", "0-65535");
                    portElement.SetAttribute("protocol", "tcp");
                    ruleElement.AppendChild(portElement);
                }

                // create and add either drop or accept element
                if (drop)
                {
                    var dropElement = doc.CreateElement("drop");
                    ruleElement.AppendChild(dropElement);
                }
                else
                {
                    var acceptElement = doc.CreateElement("accept");
                    ruleElement.AppendChild(acceptElement);
                }
            }

            UpsertXmlRule(doc, ruleIP4, "ipv4", drop, priority, allowedPorts);
            UpsertXmlRule(doc, ruleIP6, "ipv6", drop, priority, allowedPorts);

            // remove global allow rules
            foreach (var ruleNode in doc.SelectNodes("//rule"))
            {
                if (ruleNode is XmlElement ruleElement)
                {
                    var sourceElement = ruleElement.SelectSingleNode("source") as XmlElement;
                    if (sourceElement is not null)
                    {
                        var address = sourceElement.GetAttribute("address");
                        if (address == "0.0.0.0/0" || address == "::/0")
                        {
                            var portElement = ruleElement.SelectSingleNode("port") as XmlElement;
                            var port = portElement?.GetAttribute("port");
                            if (port == "0-65535")
                            {
                                var protocol = portElement?.GetAttribute("protocol");
                                if (protocol == "tcp" || protocol == "udp")
                                {
                                    ruleElement.ParentNode.RemoveChild(ruleElement);
                                }
                            }
                        }
                    }
                }
            }

            static void AddAllowAllRule(XmlDocument doc, string protocol, string family, string ips)
            {
                // allow all ipv4
                var allowIP = doc.CreateElement("rule");
                allowIP.SetAttribute("priority", "100");
                allowIP.SetAttribute("family", family);
                var allowIPSource = doc.CreateElement("source");
                allowIPSource.SetAttribute("address", ips);
                allowIP.AppendChild(allowIPSource);
                var allowIPPort = doc.CreateElement("port");
                allowIPPort.SetAttribute("port", "0-65535");
                allowIPPort.SetAttribute("protocol", protocol);
                allowIP.AppendChild(allowIPPort);
                var allowIPAccept = doc.CreateElement("accept");
                allowIP.AppendChild(allowIPAccept);
                doc.DocumentElement.AppendChild(allowIP);
            }

            AddAllowAllRule(doc, "tcp", "ipv4", "0.0.0.0/0");
            AddAllowAllRule(doc, "udp", "ipv4", "0.0.0.0/0");
            AddAllowAllRule(doc, "tcp", "ipv6", "::/0");
            AddAllowAllRule(doc, "udp", "ipv6", "::/0");

            // make sure forward node is removed
            var forwardNode = doc.SelectSingleNode("//forward") as XmlElement;
            forwardNode?.ParentNode.RemoveChild(forwardNode);

            if (canUseForwardNode)
            {
                // add forward element if supported
                forwardNode = doc.CreateElement("forward");
                forwardNode.IsEmpty = true;
                doc.DocumentElement.AppendChild(forwardNode);
            }

            // pretty print
            XDocument xDoc = XDocument.Parse(doc.OuterXml);
            var xml = xDoc.ToString();

            // write the zone file back out and reload the firewall
            ExtensionMethods.Retry(() => File.WriteAllText(zoneFile, xml, ExtensionMethods.Utf8EncodingNoPrefix));
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
            Dictionary<string, bool> rules = [];
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

        private static void EnsureZoneFile(string zoneFile, string zoneFileOrig, string fallbackZoneFileContents)
        {
            if (!File.Exists(zoneFile))
            {
                string origZoneFileContents;
                if (!File.Exists(zoneFileOrig))
                {
                    origZoneFileContents = string.IsNullOrWhiteSpace(fallbackZoneFileContents) ? defaultFallbackZoneFileContents : fallbackZoneFileContents;
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
