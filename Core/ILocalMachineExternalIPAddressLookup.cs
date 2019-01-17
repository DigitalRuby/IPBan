using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IPBan
{
    /// <summary>
    /// Look up external ip address for this machine
    /// </summary>
    public interface ILocalMachineExternalIPAddressLookup
    {
        /// <summary>
        /// Get the external ip address of this machine
        /// </summary>
        /// <param name="requestMaker">Request maker</param>
        /// <param name="url">Url to resolve with</param>
        /// <returns>External ip address</returns>
        Task<System.Net.IPAddress> LookupExternalIPAddressAsync(IHttpRequestMaker requestMaker, string url);
    }

    public class LocalMachineExternalIPAddressLookupDefault : ILocalMachineExternalIPAddressLookup
    {
        /// <summary>
        /// Singleton of LocalMachineExternalIPAddressLookupDefault
        /// </summary>
        public static LocalMachineExternalIPAddressLookupDefault Instance { get; } = new LocalMachineExternalIPAddressLookupDefault();

        public async Task<System.Net.IPAddress> LookupExternalIPAddressAsync(IHttpRequestMaker requestMaker, string url)
        {
            byte[] bytes = await requestMaker.MakeRequestAsync(new Uri(url));
            string ipString = Encoding.UTF8.GetString(bytes).Trim();
            if (System.Net.IPAddress.TryParse(ipString, out System.Net.IPAddress ipAddress))
            {
                if (ipAddress.IsIPv4MappedToIPv6)
                {
                    ipAddress = ipAddress.MapToIPv4();
                }
            }
            else
            {
                ipAddress = System.Net.IPAddress.Loopback;
            }
            return ipAddress;
        }
    }

    /// <summary>
    /// Test version of ILocalMachineExternalIPAddressLookup for tests that just need it to work without network requests
    /// </summary>
    public class LocalMachineExternalIPAddressLookupTest : ILocalMachineExternalIPAddressLookup
    {
        /// <summary>
        /// Singleton of ExternalIPAddressLookupTest
        /// </summary>
        public static LocalMachineExternalIPAddressLookupTest Instance { get; } = new LocalMachineExternalIPAddressLookupTest();

        public Task<IPAddress> LookupExternalIPAddressAsync(IHttpRequestMaker requestMaker, string url)
        {
            return Task.FromResult(System.Net.IPAddress.Loopback);
        }
    }
}
