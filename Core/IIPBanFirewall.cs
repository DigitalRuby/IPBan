using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace IPBan
{
    public interface IIPBanFirewall
    {
        /// <summary>
        /// Ensure the firewall is initialized
        /// </summary>
        void Initialize(string rulePrefix);

        /// <summary>
        /// Creates new rules to block all the ip addresses, and removes any left-over rules. Exceptions are logged.
        /// Pass an empty list to remove all blocked ip addresses.
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <returns>True if success, false if error</returns>
        bool BlockIPAddresses(IEnumerable<string> ipAddresses);

        /// <summary>
        /// Deletes any existing rule prefixed by ruleNamePrefix then creates a new rule(s) prefixed by ruleNamePrefix with block rules for all ranges specified. Exceptions are logged.
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix</param>
        /// <param name="ranges">Ranges to block</param>
        /// <param name="allowedPorts">Allowed ports, any port not in this list is blocked</param>
        /// <returns>True if success, false if error</returns>
        bool BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, params PortRange[] allowedPorts);

        /// <summary>
        /// Creates new rules to allow all the ip addresses on all ports, and removes any left-over rules. Exceptions are logged.
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <returns>True if success, false if error</returns>
        bool AllowIPAddresses(IEnumerable<string> ipAddresses);

        /// <summary>
        /// Checks if an ip address is blocked in the firewall
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if the ip address is blocked in the firewall, false otherwise</returns>
        bool IsIPAddressBlocked(string ipAddress);

        /// <summary>
        /// Checks if an ip address is explicitly allowed in the firewall
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if explicitly allowed, false if not</returns>
        bool IsIPAddressAllowed(string ipAddress);

        /// <summary>
        /// Get all rules with the specified rule name prefix
        /// </summary>
        /// <param name="ruleNamePrefix">Rule name prefix or null for default</param>
        /// <returns></returns>
        IEnumerable<string> GetRuleNames(string ruleNamePrefix = null);

        /// <summary>
        /// Gets all banned ip addresses
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
    }
}
