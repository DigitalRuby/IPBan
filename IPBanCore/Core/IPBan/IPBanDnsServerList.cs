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
using System.Net;
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
        private HashSet<IPAddress> dnsServers = new();

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
            GC.SuppressFinalize(this);
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
                    HashSet<IPAddress> newDnsServers = new(NetworkUtility.GetLocalDnsServers());
                    foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
                    {
                        newDnsServers.Add(ip);
                    }
                    dnsServers = newDnsServers;
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
