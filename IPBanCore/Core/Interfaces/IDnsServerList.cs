using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Get a list of dns servers
    /// </summary>
    public interface IDnsServerList : IUpdater
    {
        /// <summary>
        /// Check if an ip address is a dns server
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <returns>True if the ip address is a dns server, false otherwise</returns>
        bool ContainsIPAddress(IPAddress ipAddress);

        /// <summary>
        /// Check if an ip address range contains a dns server
        /// </summary>
        /// <param name="range">IP address range</param>
        /// <returns>True if the ip address range contains a dns server, false otherwise</returns>
        bool ContainsIPAddressRange(IPAddressRange range);
    }
}
