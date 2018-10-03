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
        /// <returns>Task</returns>
        Task<byte[]> DownloadDataAsync(string url);
    }

    /// <summary>
    /// Represents an http request
    /// </summary>
    public interface IHttpRequest
    {
        /// <summary>
        /// The requested uri
        /// </summary>
        Uri Uri { get; }

        /// <summary>
        /// The remove ip address of the connecting client
        /// </summary>
        IPAddress RemoteIPAddress { get; }

        /// <summary>
        /// Connection specific state
        /// </summary>
        Dictionary<object, object> Items { get; }
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
        public Task<byte[]> DownloadDataAsync(string url)
        {
            Interlocked.Increment(ref requestCount);
            using (WebClient client = new WebClient())
            {
                Assembly a = (Assembly.GetEntryAssembly() ?? IPBanService.GetIPBanAssembly());
                client.UseDefaultCredentials = true;
                client.Headers["User-Agent"] = a.GetName().Name;
                return client.DownloadDataTaskAsync(url);
            }
        }
    }

    /// <summary>
    /// Represents a default http request
    /// </summary>
    public class DefaultHttpRequest : IHttpRequest
    {
        /// <summary>
        /// Uri
        /// </summary>
        public Uri Uri { get; set; }

        /// <summary>
        /// Client remote ip address
        /// </summary>
        public IPAddress RemoteIPAddress { get; set; }

        /// <summary>
        /// Client specific state
        /// </summary>
        public Dictionary<object, object> Items { get; } = new Dictionary<object, object>();
    }
}
