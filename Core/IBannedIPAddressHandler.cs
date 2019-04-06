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
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// Handle for banned ip addresses
    /// </summary>
    public interface IBannedIPAddressHandler
    {
        /// <summary>
        /// Handle a banned ip address
        /// </summary>
        /// <param name="ipAddress">Banned ip address</param>
        /// <param name="source">Source</param>
        /// <param name="userName">User name</param>
        /// <param name="osName">OS name</param>
        /// <param name="osVersion">OS version</param>
        /// <param name="assemblyVersion">Assembly version</param>
        /// <param name="requestMaker">Request maker if needed, null otherwise</param>
        /// <returns>Task</returns>
        System.Threading.Tasks.Task HandleBannedIPAddress(string ipAddress, string source, string userName,
            string osName, string osVersion, string assemblyVersion, IHttpRequestMaker requestMaker);

        /// <summary>
        /// Base url for any http requests that need to be made
        /// </summary>
        string BaseUrl { get; set; }
    }

    /// <summary>
    /// Default banned ip address handler
    /// </summary>
    public class DefaultBannedIPAddressHandler : IBannedIPAddressHandler
    {
        /// <summary>
        /// Base url
        /// </summary>
        public string BaseUrl { get; set; } = "https://api.ipban.com";

        /// <inheritdoc />
        public Task HandleBannedIPAddress(string ipAddress, string source, string userName, string osName, string osVersion, string assemblyVersion, IHttpRequestMaker requestMaker)
        {
            if (requestMaker == null)
            {
                return Task.CompletedTask;
            }

            try
            {
                if (!System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj) || ipAddressObj.IsInternal())
                {
                    return Task.CompletedTask;
                }

                // submit url to ipban public database so that everyone can benefit from an aggregated list of banned ip addresses
                string timestamp = IPBanService.UtcNow.ToString("o");
                string url = $"/IPSubmitBanned?ip={ipAddress.UrlEncode()}&osname={osName.UrlEncode()}&osversion={osVersion.UrlEncode()}&source={source.UrlEncode()}&timestamp={timestamp.UrlEncode()}&userName={userName.UrlEncode()}&version={assemblyVersion.UrlEncode()}";
                string hash = Convert.ToBase64String(new SHA256Managed().ComputeHash(Encoding.UTF8.GetBytes(url + IPBanResources.IPBanKey1)));
                url += "&hash=" + hash.UrlEncode();
                url = BaseUrl + url;
                return requestMaker.MakeRequestAsync(new Uri(url));
            }
            catch
            {
                // don't care, this is not fatal
                return Task.CompletedTask;
            }
        }
    }
}
