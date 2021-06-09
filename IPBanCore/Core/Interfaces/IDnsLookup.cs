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
using System.Net;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Simple DNS interface to lookup data about ip address or host name
    /// </summary>
    public interface IDnsLookup
    {
        /// <summary>
        /// Get ip addresses from a host name or ip address
        /// </summary>
        /// <param name="hostNameOrAddress">Host name or ip address</param>
        /// <returns>IP addresses</returns>
        Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress);

        /// <summary>
        /// Get a host entry
        /// </summary>
        /// <param name="hostNameOrAddress">Host name or ip address</param>
        /// <returns>Host entry</returns>
        Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress);

        /// <summary>
        /// Get host name of local machine
        /// </summary>
        /// <param name="hostNameOrAddress">Host name or ip address to get host name for or null for local machine host name</param>
        /// <returns>Host name of local machine</returns>
        Task<string> GetHostNameAsync(string hostNameOrAddress = null);
    }

    /// <summary>
    /// Default implementation of IDnsLookup, uses Dns class
    /// </summary>
    public class DefaultDnsLookup : IDnsLookup
    {
        /// <summary>
        /// Singleton of DefaultDnsLookup
        /// </summary>
        public static DefaultDnsLookup Instance { get; } = new DefaultDnsLookup();

        public Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress)
        {
            return Dns.GetHostAddressesAsync(hostNameOrAddress);
        }

        public Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress)
        {
            return Dns.GetHostEntryAsync(hostNameOrAddress);
        }

        public async Task<string> GetHostNameAsync(string hostNameOrAddress = null)
        {
            if (string.IsNullOrWhiteSpace(hostNameOrAddress))
            {
                return Dns.GetHostName();
            }
            string hostName = (await Dns.GetHostEntryAsync(hostNameOrAddress)).HostName;
            return hostName;
        }

        public static IPAddress GetLocalIPAddress()
        {
            try
            {
                IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress local = null;
                foreach (IPAddress ip in host.AddressList)
                {
                    if (local is null || ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        local = ip;
                    }

                }
                if (local is null)
                {
                    throw new ApplicationException("Unable to determine local ip address, is the network adapter enabled?");
                }
                return local.Clean();
            }
            catch
            {

            }
            return null;
        }
    }

    /// <summary>
    /// Test dns lookup for easy use in unit tests
    /// </summary>
    public class TestDnsLookup : IDnsLookup
    {
        /// <summary>
        /// Singleton of TestDnsLookup
        /// </summary>
        public static TestDnsLookup Instance { get; } = new TestDnsLookup();

        Task<System.Net.IPAddress[]> IDnsLookup.GetHostAddressesAsync(string hostNameOrAddress)
        {
            return Task.FromResult(new[] { System.Net.IPAddress.Parse("10.10.10.10") });
        }

        Task<IPHostEntry> IDnsLookup.GetHostEntryAsync(string hostNameOrAddress)
        {
            return Task.FromResult(new IPHostEntry { AddressList = new[] { System.Net.IPAddress.Parse("10.10.10.10") }, HostName = hostNameOrAddress });
        }

        async Task<string> IDnsLookup.GetHostNameAsync(string hostNameOrAddress)
        {
            if (string.IsNullOrWhiteSpace(hostNameOrAddress))
            {
                return Dns.GetHostName();
            }
            return (await Dns.GetHostEntryAsync(hostNameOrAddress)).HostName;
        }
    }
}
