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
using System.Collections.Generic;
using System.IO.Compression;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Simple interface that can make http requests
    /// </summary>
    public interface IHttpRequestMaker
    {
        /// <summary>
        /// Make a GET or POST http request
        /// </summary>
        /// <param name="uri">Uri</param>
        /// <param name="postJson">Optional json to post for a POST request, else GET is used</param>
        /// <param name="headers">Optional http headers</param>
        /// <param name="method">Override the method</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task of response byte[]</returns>
        Task<byte[]> MakeRequestAsync(Uri uri,
            byte[] postJson = null,
            IEnumerable<KeyValuePair<string, object>> headers = null,
            string method = null,
            CancellationToken cancelToken = default);
    }

    /// <summary>
    /// Default implementation of IHttpRequestMaker
    /// </summary>
    public class DefaultHttpRequestMaker : IHttpRequestMaker
    {
        private static readonly HttpClient client = new();

        /// <summary>
        /// Singleton of DefaultHttpRequestMaker
        /// </summary>
        public static DefaultHttpRequestMaker Instance { get; } = new DefaultHttpRequestMaker();

        /// <summary>
        /// Whether live requests should be disabled (unit tests)
        /// </summary>
        public static bool DisableLiveRequests { get; set; }

        private static long liveRequestCount;
        /// <summary>
        /// Global counter of live requests made
        /// </summary>
        public static long LiveRequestCount { get { return liveRequestCount; } }

        private static long localRequestCount;
        /// <summary>
        /// Global counter of local requests made
        /// </summary>
        public static long LocalRequestCount { get { return localRequestCount; } }

        /// <inheritdoc />
        public async Task<byte[]> MakeRequestAsync(Uri uri,
            byte[] postJson = null,
            IEnumerable<KeyValuePair<string, object>> headers = null,
            string method = null,
            CancellationToken cancelToken = default)
        {
            if (uri.Host.StartsWith("localhost", StringComparison.OrdinalIgnoreCase) ||
                uri.Host.StartsWith("127.0.0.1") ||
                uri.Host.StartsWith("::1"))
            {
                Interlocked.Increment(ref localRequestCount);
            }
            else if (DisableLiveRequests)
            {
                throw new InvalidOperationException("Live requests have been disabled, cannot process url " + uri.ToString());
            }
            else
            {
                Interlocked.Increment(ref liveRequestCount);
            }
            Assembly versionAssembly = Assembly.GetEntryAssembly();
            if (versionAssembly is null)
            {
                versionAssembly = Assembly.GetAssembly(typeof(IPBanService));
                if (versionAssembly is null)
                {
                    versionAssembly = GetType().Assembly;
                }
            }
            HttpRequestMessage msg = new()
            {
                RequestUri = uri
            };
            msg.Headers.Add("User-Agent", versionAssembly.GetName().Name);
            if (headers != null)
            {
                foreach (KeyValuePair<string, object> header in headers)
                {
                    msg.Headers.Add(header.Key, header.Value.ToHttpHeaderString());
                }
            }
            byte[] response;
            if (postJson is null || postJson.Length == 0)
            {
                msg.Method = HttpMethod.Get;
            }
            else
            {
                msg.Method = HttpMethod.Post;
                msg.Headers.Add("Cache-Control", "no-cache");
                msg.Content = new ByteArrayContent(postJson);
                msg.Content.Headers.Add("Content-Type", "application/json; charset=utf-8");
            }

            // set override method if available
            if (!string.IsNullOrWhiteSpace(method))
            {
                msg.Method = new HttpMethod(method);
            }

            var responseMsg = await client.SendAsync(msg, cancelToken);
            response = await responseMsg.Content.ReadAsByteArrayAsync(cancelToken);
            if (!responseMsg.IsSuccessStatusCode)
            {
                throw new HttpRequestException("Request to url " + uri + " failed, status: " + responseMsg.StatusCode + ", response: " + Encoding.UTF8.GetString(response),
                    null, responseMsg.StatusCode);
            }
            else if (response is not null &&
                response.Length != 0 &&
                uri.AbsolutePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    // in case response somehow got gzip decompressed already, catch exception and keep response as is
                    MemoryStream decompressStream = new();
                    {
                        using GZipStream gz = new(new MemoryStream(response), CompressionMode.Decompress, true);
                        gz.CopyTo(decompressStream);
                    }
                    response = decompressStream.ToArray();
                }
                catch
                {
                }
            }
            return response;
        }
    }
}
