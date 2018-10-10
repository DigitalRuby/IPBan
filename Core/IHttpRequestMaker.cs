using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IPBan
{
    /// <summary>
    /// Simple interface that can make http requests
    /// </summary>
    public interface IHttpRequestMaker
    {
        /// <summary>
        /// GET request and retrieve raw data
        /// </summary>
        /// <param name="url">Url</param>
        /// <param name="headers">Optional http headers</param>
        /// <returns>Task</returns>
        Task<byte[]> DownloadDataAsync(string url, params KeyValuePair<string, string>[] headers);
    }

    /// <summary>
    /// Default implementation of IHttpRequestMaker
    /// </summary>
    public class DefaultHttpRequestMaker : IHttpRequestMaker
    {
        private static long requestCount;
        /// <summary>
        /// Global counter of requests made
        /// </summary>
        public static long RequestCount { get { return requestCount; } }

        /// <summary>
        /// Download data from a URL using GET method
        /// </summary>
        /// <param name="url">Url</param>
        /// <returns>Raw bytes</returns>
        public Task<byte[]> DownloadDataAsync(string url, params KeyValuePair<string, string>[] headers)
        {
            Interlocked.Increment(ref requestCount);
            using (WebClient client = new WebClient())
            {
                Assembly a = (Assembly.GetEntryAssembly() ?? IPBanService.GetIPBanAssembly());
                client.UseDefaultCredentials = true;
                client.Headers["User-Agent"] = a.GetName().Name;
                foreach (KeyValuePair<string, string> header in headers)
                {
                    client.Headers[header.Key] = header.Value;
                }
                return client.DownloadDataTaskAsync(url);
            }
        }
    }
}
