using System;
using System.Collections.Generic;
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
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <returns>True if success, false if error</returns>
        bool CreateRules(IReadOnlyList<string> ipAddresses);

        /// <summary>
        /// Delete all rules with a name beginning with the rule prefix. Exceptions are logged.
        /// </summary>
        /// <param name="startIndex">The start index to begin deleting rules at. The index is appended to the rule prefix. Not all platforms use the index.</param>
        /// <returns>True if success, false if error</returns>
        bool DeleteRules(int startIndex = 0);

        /// <summary>
        /// Checks if an ip address is blocked in the firewall
        /// </summary>
        /// <param name="ipAddress">IPAddress</param>
        /// <returns>True if the ip address is blocked in the firewall, false otherwise</returns>
        bool IsIPAddressBlocked(string ipAddress);

        /// <summary>
        /// Gets all banned ip addresses
        /// </summary>
        /// <returns>IEnumerable of all ip addresses</returns>
        IEnumerable<string> EnumerateBannedIPAddresses();
    }
}
