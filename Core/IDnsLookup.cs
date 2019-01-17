using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IPBan
{
    /// <summary>
    /// Simple DNS interface to lookup data about ip address or host name
    /// </summary>
    public interface IDnsLookup
    {
        /// <summary>
        /// Get a host entry
        /// </summary>
        /// <param name="hostNameOrAddress">Host name or ip address</param>
        /// <returns>IPHostEntry</returns>
        Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress);

        /// <summary>
        /// Get ip addresses from a host name or ip address
        /// </summary>
        /// <param name="hostNameOrAddress">Host name or ip address</param>
        /// <returns>IP addresses</returns>
        Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress);
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

        public static IPAddress GetLocalIPAddress()
        {
            try
            {
                IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (IPAddress ip in host.AddressList)
                {
                    if (ip.IsIPv4MappedToIPv6)
                    {
                        return ip.MapToIPv4();
                    }
                    return ip;
                }
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

        Task<IPHostEntry> IDnsLookup.GetHostEntryAsync(string hostNameOrAddress)
        {
            return Task.FromResult(new IPHostEntry { HostName = hostNameOrAddress, AddressList = new System.Net.IPAddress[] { System.Net.IPAddress.Parse("10.10.10.10") } });
        }

        Task<System.Net.IPAddress[]> IDnsLookup.GetHostAddressesAsync(string hostNameOrAddress)
        {
            return Task.FromResult(new System.Net.IPAddress[1] { System.Net.IPAddress.Parse("10.10.10.10") });
        }
    }
}
