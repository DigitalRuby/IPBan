using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IPBan
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
                if (System.Diagnostics.Debugger.IsAttached || !System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj) || ipAddressObj.IsInternal())
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
