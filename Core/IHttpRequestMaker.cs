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
        /// Make a GET or POST http request
        /// </summary>
        /// <param name="url">Url</param>
        /// <param name="postJson">Optional json to post for a POST request, else GET is used</param>
        /// <param name="headers">Optional http headers</param>
        /// <returns>Task of response byte[]</returns>
        Task<byte[]> MakeRequestAsync(string url, string postJson = null, params KeyValuePair<string, string>[] headers);
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

        public Task<byte[]> MakeRequestAsync(string url, string postJson = null, params KeyValuePair<string, string>[] headers)
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
                if (string.IsNullOrWhiteSpace(postJson))
                {
                    return client.DownloadDataTaskAsync(url);
                }
                client.Headers["Content-Type"] = "application/json";
                return client.UploadDataTaskAsync(url, "POST", Encoding.UTF8.GetBytes(postJson));
            }
        }
    }
}
