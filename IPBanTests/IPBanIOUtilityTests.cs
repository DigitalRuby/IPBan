/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IOUtility.GetLines — the helper that backs the `$$file(...)` regex
macro and any operator-supplied URL or file source. This is a security-relevant
read path: it has a max-bytes cap to mitigate oversize / SSRF-leak responses,
plus URL/file routing logic. Tests cover file branch, URL branch, and the
size-cap behavior on each.
*/

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanIOUtilityTests
    {
        // -------------------- file branch --------------------

        [Test]
        public void GetLines_FilePath_ReturnsAllLines()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_io_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(path, "1.2.3.4\n5.6.7.8\n9.9.9.9");
                string[] lines = IOUtility.GetLines(path);
                CollectionAssert.AreEqual(new[] { "1.2.3.4", "5.6.7.8", "9.9.9.9" }, lines);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public void GetLines_FilePath_NonexistentReturnsEmpty()
        {
            // A missing file must NOT throw — GetLines is called from log-scanning hot paths
            // where any exception would tear down the cycle.
            string[] lines = IOUtility.GetLines("/nonexistent/path/does/not/exist.txt");
            CollectionAssert.IsEmpty(lines);
        }

        [Test]
        public void GetLines_FilePath_RespectsMaxBytesCap()
        {
            // Files larger than maxBytes must return [] without reading the body — this is
            // the size-bound that prevents an operator-supplied or attacker-influenced file
            // from chewing memory in IPBanRegexParser.
            string path = Path.Combine(Path.GetTempPath(), "ipban_io_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                // 200 bytes of content
                File.WriteAllText(path, new string('a', 200));

                // cap below file size → must come back empty
                CollectionAssert.IsEmpty(IOUtility.GetLines(path, maxBytes: 100));

                // cap above file size → returns content
                string[] lines = IOUtility.GetLines(path, maxBytes: 1000);
                ClassicAssert.AreEqual(1, lines.Length);
                ClassicAssert.AreEqual(200, lines[0].Length);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public void GetLines_FilePath_MaxBytesZeroMeansNoCap()
        {
            // maxBytes <= 0 disables the cap entirely (per the docs).
            string path = Path.Combine(Path.GetTempPath(), "ipban_io_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(path, "line1\nline2");
                string[] lines = IOUtility.GetLines(path, maxBytes: 0);
                CollectionAssert.AreEqual(new[] { "line1", "line2" }, lines);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        // -------------------- URL branch (real local HttpListener) --------------------

        [Test]
        public void GetLines_Url_ReturnsBodyLinesTrimmedAndNonEmpty()
        {
            // GetLines uses TrimEntries|RemoveEmptyEntries on URL responses, so leading/
            // trailing whitespace and blank lines should be filtered out.
            using var server = LocalHttpServer.Start(ctx =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes("  1.2.3.4 \n\n5.6.7.8\n  \n9.9.9.9\n");
                ctx.Response.ContentLength64 = bytes.Length;
                ctx.Response.ContentType = "text/plain";
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            });

            string[] lines = IOUtility.GetLines(server.Url);
            CollectionAssert.AreEqual(new[] { "1.2.3.4", "5.6.7.8", "9.9.9.9" }, lines);
        }

        [Test]
        public void GetLines_Url_NonSuccessStatusReturnsEmpty()
        {
            // Server returns 500 → GetLines must come back empty without throwing.
            using var server = LocalHttpServer.Start(ctx =>
            {
                ctx.Response.StatusCode = 500;
                ctx.Response.ContentLength64 = 0;
            });

            string[] lines = IOUtility.GetLines(server.Url);
            CollectionAssert.IsEmpty(lines);
        }

        [Test]
        public void GetLines_Url_RespectsMaxBytesContentLength()
        {
            // When the response advertises a Content-Length larger than maxBytes, GetLines
            // must return [] without consuming the body. We send a huge declared length but
            // a tiny body so the test stays fast — only Content-Length matters for the cap.
            using var server = LocalHttpServer.Start(ctx =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes("dummy\n");
                ctx.Response.ContentLength64 = 100_000; // far above the cap below
                ctx.Response.ContentType = "text/plain";
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            });

            CollectionAssert.IsEmpty(IOUtility.GetLines(server.Url, maxBytes: 1024));
        }

        [Test]
        public void GetLines_Url_MaxBytesAboveContentLengthAllowsResponse()
        {
            using var server = LocalHttpServer.Start(ctx =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes("yes\n");
                ctx.Response.ContentLength64 = bytes.Length;
                ctx.Response.ContentType = "text/plain";
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            });

            string[] lines = IOUtility.GetLines(server.Url, maxBytes: 10_000);
            CollectionAssert.AreEqual(new[] { "yes" }, lines);
        }

        [Test]
        public void GetLines_UnreachableUrl_ReturnsEmptyDoesNotThrow()
        {
            // No server listening; the HttpClient call should fail and GetLines should
            // swallow the exception and return [] — the function is a "best effort" read.
            string[] lines = IOUtility.GetLines("http://127.0.0.1:1/never-listening");
            CollectionAssert.IsEmpty(lines);
        }

        // -------------------- helpers --------------------

        /// <summary>
        /// Tiny in-process HttpListener for URL-branch tests. Picks a free localhost port and
        /// runs each request through a caller-supplied handler. Disposing stops the listener.
        /// </summary>
        private sealed class LocalHttpServer : IDisposable
        {
            public string Url { get; }
            private readonly HttpListener listener;
            private readonly CancellationTokenSource cts = new();
            private readonly Task loop;

            private LocalHttpServer(string url, HttpListener l, Action<HttpListenerContext> handler)
            {
                Url = url;
                listener = l;
                loop = Task.Run(async () =>
                {
                    while (!cts.IsCancellationRequested)
                    {
                        HttpListenerContext ctx;
                        try { ctx = await listener.GetContextAsync().WaitAsync(cts.Token); }
                        catch { return; }
                        try { handler(ctx); }
                        catch { /* test handlers shouldn't fail; ignore if they do */ }
                        finally
                        {
                            try { ctx.Response.Close(); } catch { /* best effort */ }
                        }
                    }
                });
            }

            public static LocalHttpServer Start(Action<HttpListenerContext> handler)
            {
                // Find a free port via TcpListener bind-to-zero trick, then hand that port to
                // HttpListener which can't bind to port 0 directly.
                var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                int port = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();

                string prefix = $"http://127.0.0.1:{port}/";
                var listener = new HttpListener();
                listener.Prefixes.Add(prefix);
                listener.Start();
                return new LocalHttpServer(prefix, listener, handler);
            }

            public void Dispose()
            {
                cts.Cancel();
                try { listener.Stop(); } catch { /* best effort */ }
                try { listener.Close(); } catch { /* best effort */ }
                try { loop.Wait(1000); } catch { /* best effort */ }
                cts.Dispose();
            }
        }
    }
}
