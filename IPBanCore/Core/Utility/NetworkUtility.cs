using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace DigitalRuby.IPBanCore.Core.Utility
{
    /// <summary>
    /// Network utility methods
    /// </summary>
    public static class NetworkUtility
    {
        /// <summary>
        /// Get the local configured dns servers for this machine from all network interfaces
        /// </summary>
        /// <returns>All dns servers for this local machine</returns>
        public static IReadOnlyCollection<IPAddress> GetLocalDnsServers()
        {
            List<IPAddress> dnsServers = new List<IPAddress>();
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                    IPAddressCollection dnsAddresses = ipProperties.DnsAddresses;
                    dnsServers.AddRange(dnsAddresses);
                }
            }

            return dnsServers;
        }
    }
}
