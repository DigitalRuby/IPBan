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
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Look up external ip address for this machine using http get
    /// </summary>
    public interface ILocalMachineExternalIPAddressLookup
    {
        /// <summary>
        /// Get the external ip address of this machine
        /// </summary>
        /// <param name="requestMaker">Request maker or null for default</param>
        /// <param name="url">Url to resolve with or null for default</param>
        /// <returns>External ip address</returns>
        Task<System.Net.IPAddress> LookupExternalIPAddressAsync(IHttpRequestMaker requestMaker = null, string url = null);
    }

    /// <summary>
    /// Look up external ip address for this machine using http get
    /// </summary>
    public class LocalMachineExternalIPAddressLookupDefault : ILocalMachineExternalIPAddressLookup
    {
        /// <summary>
        /// Singleton of LocalMachineExternalIPAddressLookupDefault
        /// </summary>
        public static LocalMachineExternalIPAddressLookupDefault Instance { get; } = new LocalMachineExternalIPAddressLookupDefault(DefaultHttpRequestMaker.Instance);

        private readonly IHttpRequestMaker requestMaker;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="requestMaker">Request maker</param>
        public LocalMachineExternalIPAddressLookupDefault(IHttpRequestMaker requestMaker)
        {
            requestMaker.ThrowIfNull();
            this.requestMaker = requestMaker;
        }

        /// <summary>
        /// Get external ip address of the local machine.
        /// The url should the ip address in text format, and may contain comma separated ip addresses, in which case the last value will be used.
        /// </summary>
        /// <param name="requestMaker">Request maker or null for default</param>
        /// <param name="url">Url or null for default</param>
        /// <returns>IP address</returns>
        public async Task<System.Net.IPAddress> LookupExternalIPAddressAsync(IHttpRequestMaker requestMaker = null, string url = null)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                url = "https://checkip.amazonaws.com";
            }
            byte[] bytes = null;
            Exception ex = null;

            // try up to 3 times to get external ip
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    bytes = await (requestMaker ?? this.requestMaker).MakeRequestAsync(new Uri(url));
                    break;
                }
                catch (Exception _ex)
                {
                    ex = _ex;
                    await Task.Delay(1000);
                }
            }

            if (bytes is null)
            {
                throw new System.Net.WebException("Unable to get external ip address", ex);
            }
            string ipString = Encoding.UTF8.GetString(bytes).Split(',').Last().Trim();
            if (System.Net.IPAddress.TryParse(ipString, out System.Net.IPAddress ipAddress))
            {
                ipAddress = ipAddress.Clean();
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

        /// <summary>
        /// Just returns loopback ip
        /// </summary>
        /// <param name="requestMaker">N/A</param>
        /// <param name="url">N/A</param>
        /// <returns>Loopback ip</returns>
        public Task<IPAddress> LookupExternalIPAddressAsync(IHttpRequestMaker requestMaker = null, string url = null)
        {
            return Task.FromResult(System.Net.IPAddress.Loopback);
        }
    }
}
