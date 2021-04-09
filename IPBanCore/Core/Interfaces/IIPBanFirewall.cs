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
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    public interface IIPBanFirewall : IUpdater, IDisposable
    {
        /// <summary>
        /// Creates/updates rules to block all the ip addresses, and removes any left-over rules. Exceptions are logged.
        /// Pass an empty list to remove all blocked ip addresses for the ruleNamePrefix.
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix, can be null for the default block rule</param>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <param name="allowedPorts">Allowed ports, any port not in this list is blocked</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <summary>
        /// Same as BlockIPAddresses except this is a delta that only adds / removes the necessary ip, all other ip are left alone.
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix, required</param>
        /// <param name="ipAddresses">IP Addresses (delta)</param>
        /// <param name="allowedPorts">Allowed ports, any port not in this list is blocked, null to block all ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <summary>
        /// Creates/updates new rule(s) prefixed by ruleNamePrefix with block rules for all ranges specified. Exceptions are logged.
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix, required</param>
        /// <param name="ranges">Ranges to block</param>
        /// <param name="allowedPorts">Allowed ports, any port not in this list is blocked, null to block all ports</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <summary>
        /// Creates new rules to allow all the ip addresses on all ports, and removes any left-over rules. Exceptions are logged.
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default);

        /// <summary>
        /// Creates/updates rules to allow all the ip addresses, and removes any left-over rules. Exceptions are logged.
        /// Pass an empty list to remove all allowed ip addresses for the ruleNamePrefix.
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix, required</param>
        /// <param name="ipAddresses">IP Addresses or ranges</param>
        /// <param name="allowedPorts">Allowed ports, any port not in this list is blocked</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>True if success, false if error</returns>
        Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <summary>
        /// Checks if an ip address is blocked in the firewall
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <param name="ruleName">Found rule name if known by the firewall implementation if ip is blocked, otherwise null</param>
        /// <param name="port">Optional port, -1 to not check the port. Not all firewalls will check the port.</param>
        /// <returns>True if the ip address is blocked in the firewall, false otherwise</returns>
        bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1);

        /// <summary>
        /// Checks if an ip address is blocked in the firewall
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <param name="port">Optional port, -1 to not check the port. Not all firewalls will check the port.</param>
        /// <returns>True if the ip address is blocked in the firewall, false otherwise</returns>
        bool IsIPAddressBlocked(string ipAddress, int port = -1) => IsIPAddressBlocked(ipAddress, out _, port);

        /// <summary>
        /// Checks if an ip address is explicitly allowed in the firewall
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <param name="port">Optional port, -1 to not check the port. Not all firewalls will check the port.</param>
        /// <returns>True if explicitly allowed, false if not</returns>
        bool IsIPAddressAllowed(string ipAddress, int port = -1);

        /// <summary>
        /// Get all rules with the specified rule name prefix
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix or null for default</param>
        /// <returns></returns>
        IEnumerable<string> GetRuleNames(string ruleNamePrefix = null);

        /// <summary>
        /// Delete the rule with the specified name
        /// </summary>
        /// <param name="ruleName">Rule name</param>
        /// <returns>True if success, false if failure</returns>
        bool DeleteRule(string ruleName);

        /// <summary>
        /// Gets all banned ip addresses from BlockIPAddresses calls using the built in block rule
        /// </summary>
        /// <returns>IEnumerable of all ip addresses</returns>
        IEnumerable<string> EnumerateBannedIPAddresses();

        /// <summary>
        /// Gets all explicitly allowed ip addresses
        /// </summary>
        /// <returns>IEnumerable of all ip addresses</returns>
        IEnumerable<string> EnumerateAllowedIPAddresses();

        /// <summary>
        /// Gets all ip addresses for a rule prefix
        /// </summary>
        /// <param name="ruleNamePrefix">Rule prefix</param>
        /// <returns>IEnumerable of all ip addreses</returns>
        IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null);

        /// <summary>
        /// Remove all rules that IPBan created
        /// </summary>
        void Truncate();

        /// <summary>
        /// The rule prefix for the firewall
        /// </summary>
        string RulePrefix { get; }
    }

    /// <summary>
    /// Represents an ip address delta operation
    /// </summary>
    public struct IPBanFirewallIPAddressDelta
    {
        /// <summary>
        /// True if added, false if removed
        /// </summary>
        public bool Added { get; set; }

        /// <summary>
        /// IPAddress
        /// </summary>
        public string IPAddress { get; set; }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return $"{IPAddress} added = {Added}";
        }
    }

    /// <summary>
    /// Represents a firewall rule
    /// </summary>
    public class IPBanFirewallRule
    {
        /// <summary>
        /// Rule name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// True to block, false to allow
        /// </summary>
        public bool Block { get; set; }

        /// <summary>
        /// IP address ranges to block
        /// </summary>
        public IReadOnlyList<IPAddressRange> IPAddressRanges { get; set; }

        /// <summary>
        /// Port ranges to allow
        /// </summary>
        public IReadOnlyList<PortRange> AllowPortRanges { get; set; }

        /// <summary>
        /// Platform regex
        /// </summary>
        public Regex PlatformRegex { get; set; }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            // name
            StringBuilder b = new(Name);
            b.Append(';');

            b.Append(Block ? "block" : "allow");
            b.Append(';');

            // ip ranges
            foreach (IPAddressRange range in IPAddressRanges)
            {
                b.Append(range.ToCidrString());
                b.Append(',');
            }
            b.Length--;
            b.Append(';');

            // allow port ranges
            foreach (PortRange range in AllowPortRanges)
            {
                b.Append(range);
                b.Append(',');
            }
            b.Length--;
            b.Append(';');

            // platform regex
            b.Append(PlatformRegex.ToString());

            return b.ToString();
        }

    }
}
