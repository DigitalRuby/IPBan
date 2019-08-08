/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
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
