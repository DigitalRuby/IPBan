using DigitalRuby.IPBanCore.Core.Utility;

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Maintains a list of dns servers
    /// </summary>
    public class IPBanDnsServerList : IDnsServerList
    {
        private static readonly TimeSpan dnsServerUpdateInterval = TimeSpan.FromMinutes(1.0);
        private DateTime lastDnsServersUpdate;
        private HashSet<IPAddress> dnsServers = new HashSet<IPAddress>();

        /// <summary>
        /// Constructor
        /// </summary>
        public IPBanDnsServerList()
        {
            UpdateDnsServersIfNeeded();
        }

        /// <inheritdoc />
        public Task Update(CancellationToken cancelToken = default)
        {
            UpdateDnsServersIfNeeded();
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            
        }

        /// <inheritdoc />
        public bool ContainsIPAddress(IPAddress ipAddress)
        {
            return dnsServers.Contains(ipAddress);
        }

        /// <inheritdoc />
        public bool ContainsIPAddressRange(IPAddressRange range)
        {
            foreach (IPAddress ipAddress in dnsServers)
            {
                if (range.Contains(ipAddress))
                {
                    return true;
                }
            }
            return false;
        }

        private void UpdateDnsServersIfNeeded()
        {
            if ((IPBanService.UtcNow - lastDnsServersUpdate) > dnsServerUpdateInterval)
            {
                try
                {
                    dnsServers = new HashSet<IPAddress>(NetworkUtility.GetLocalDnsServers());
                    lastDnsServersUpdate = IPBanService.UtcNow;
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }
        }
    }
}
