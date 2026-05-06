/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanFilter's URL-source and DNS-source construction paths. The
filter constructor downloads remote IP lists via IHttpRequestMaker and resolves
DNS hostnames via IDnsLookup; both flow attacker-influenced data into the set
of "filtered" IPs and need to behave correctly in failure modes (network
errors, malformed lines, host-not-found).
*/

using System;
using System.Collections.Generic;
using System.Linq;
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
    public sealed class IPBanFilterUrlAndDnsTests
    {
        // -------------------- URL source --------------------

        [Test]
        public void Constructor_UrlSource_LoadsListedIpsAndIgnoresMalformedLines()
        {
            // The IP list at the URL has a mix of:
            //   - valid IPv4 + IPv6 addresses
            //   - blank lines (must be skipped)
            //   - garbage lines (must be skipped without crashing the constructor)
            //   - duplicate entries (must dedupe)
            byte[] payload = Encoding.UTF8.GetBytes(string.Join('\n',
                "10.0.0.1",
                "",
                "10.0.0.2",
                "not-an-ip",
                "  10.0.0.3  ",          // whitespace-padded — should still parse
                "::1",
                "10.0.0.1",               // duplicate
                "garbage-2",
                "fe80::c872:be03:5c94:4af2"));

            var http = new FakeHttpRequestMaker(payload);

            IPBanFilter filter = new(
                value: "https://example.com/ipset",
                regexValue: null,
                httpRequestMaker: http,
                dns: null,
                dnsList: null,
                counterFilter: null);

            // Each well-formed entry above should be filtered; garbage and blanks should not
            // appear in the resulting set.
            ClassicAssert.IsTrue(filter.IsFiltered("10.0.0.1", out _));
            ClassicAssert.IsTrue(filter.IsFiltered("10.0.0.2", out _));
            ClassicAssert.IsTrue(filter.IsFiltered("10.0.0.3", out _));
            ClassicAssert.IsTrue(filter.IsFiltered("::1", out _));
            ClassicAssert.IsTrue(filter.IsFiltered("fe80::c872:be03:5c94:4af2", out _));

            ClassicAssert.IsFalse(filter.IsFiltered("10.0.0.99", out _),
                "an IP not in the list must not be filtered");

            ClassicAssert.AreEqual(1, http.CallCount,
                "the URL should have been fetched exactly once during construction");
        }

        [Test]
        public void Constructor_UrlSource_HttpFailureDoesNotCrashConstructor()
        {
            // If the HTTP request throws, the constructor must catch and continue. A flaky
            // remote IP list shouldn't tear down the filter (and by extension the cycle).
            var http = new ThrowingHttpRequestMaker(new TimeoutException("simulated network failure"));

            Assert.DoesNotThrow(() =>
            {
                IPBanFilter filter = new(
                    value: "https://example.com/ipset",
                    regexValue: null,
                    httpRequestMaker: http,
                    dns: null,
                    dnsList: null,
                    counterFilter: null);

                // Filter is empty after a failed fetch, so nothing is filtered
                ClassicAssert.IsFalse(filter.IsFiltered("10.0.0.1", out _));
            });
        }

        [Test]
        public void Constructor_UrlSource_NullHttpRequestMakerSkipsUrl()
        {
            // If no IHttpRequestMaker is supplied, URL entries are silently ignored.
            // Other entries in the same value list should still be processed.
            IPBanFilter filter = new(
                value: "https://example.com/ipset, 192.168.1.1",
                regexValue: null,
                httpRequestMaker: null,
                dns: null,
                dnsList: null,
                counterFilter: null);

            ClassicAssert.IsTrue(filter.IsFiltered("192.168.1.1", out _),
                "non-URL entries must still be processed when the http maker is null");
        }

        [Test]
        public void Constructor_UrlSource_EmptyResponseBodyIsHandled()
        {
            // Empty response body — neither crash nor add anything.
            var http = new FakeHttpRequestMaker(Array.Empty<byte>());

            IPBanFilter filter = new(
                value: "https://example.com/ipset",
                regexValue: null,
                httpRequestMaker: http,
                dns: null,
                dnsList: null,
                counterFilter: null);

            ClassicAssert.IsFalse(filter.IsFiltered("1.2.3.4", out _));
        }

        // -------------------- DNS source --------------------

        [Test]
        public void Constructor_DnsSource_ResolvesHostnameAndAddsAddresses()
        {
            // A non-IP, non-URL value that's a valid hostname should resolve through the
            // injected IDnsLookup and add each returned address to the filter set.
            var dns = new FakeDnsLookup(new Dictionary<string, IPAddress[]>
            {
                ["malicious.example.com"] = new[]
                {
                    IPAddress.Parse("203.0.113.10"),
                    IPAddress.Parse("203.0.113.11"),
                }
            });

            IPBanFilter filter = new(
                value: "malicious.example.com",
                regexValue: null,
                httpRequestMaker: null,
                dns: dns,
                dnsList: null,
                counterFilter: null);

            ClassicAssert.IsTrue(filter.IsFiltered("203.0.113.10", out _));
            ClassicAssert.IsTrue(filter.IsFiltered("203.0.113.11", out _));
            ClassicAssert.IsFalse(filter.IsFiltered("203.0.113.99", out _));
        }

        [Test]
        public void Constructor_DnsSource_HostNotFoundDoesNotCrash()
        {
            // A hostname that doesn't resolve must not throw — the constructor swallows
            // SocketException(HostNotFound) by design (the entry simply produces nothing).
            var dns = new FakeDnsLookup(new Dictionary<string, IPAddress[]>())
            {
                ThrowSocketHostNotFoundOnUnknown = true,
            };

            Assert.DoesNotThrow(() =>
            {
                IPBanFilter filter = new(
                    value: "nonexistent-host-" + Guid.NewGuid().ToString("N") + ".invalid",
                    regexValue: null,
                    httpRequestMaker: null,
                    dns: dns,
                    dnsList: null,
                    counterFilter: null);
            });
        }

        // -------------------- mixed entries --------------------

        [Test]
        public void Constructor_MixedEntries_AllSourcesContribute()
        {
            // A single value list mixing literal IPs, a hostname, and a URL — all of them
            // should be merged into the filter set.
            byte[] payload = Encoding.UTF8.GetBytes("10.10.10.1\n10.10.10.2\n");
            var http = new FakeHttpRequestMaker(payload);
            var dns = new FakeDnsLookup(new Dictionary<string, IPAddress[]>
            {
                ["host.example.com"] = new[] { IPAddress.Parse("198.51.100.1") },
            });

            IPBanFilter filter = new(
                value: "1.2.3.4, host.example.com, https://example.com/ipset",
                regexValue: null,
                httpRequestMaker: http,
                dns: dns,
                dnsList: null,
                counterFilter: null);

            ClassicAssert.IsTrue(filter.IsFiltered("1.2.3.4", out _),    "literal IP");
            ClassicAssert.IsTrue(filter.IsFiltered("198.51.100.1", out _), "DNS-resolved");
            ClassicAssert.IsTrue(filter.IsFiltered("10.10.10.1", out _),  "URL-supplied");
            ClassicAssert.IsTrue(filter.IsFiltered("10.10.10.2", out _),  "URL-supplied");
        }

        // -------------------- test doubles --------------------

        private sealed class FakeHttpRequestMaker : IHttpRequestMaker
        {
            private readonly byte[] payload;
            private int callCount;
            public int CallCount => callCount;

            public FakeHttpRequestMaker(byte[] payload) { this.payload = payload; }

            public Task<byte[]> MakeRequestAsync(Uri uri,
                byte[] postJson = null,
                IEnumerable<KeyValuePair<string, object>> headers = null,
                string method = null,
                CancellationToken cancelToken = default)
            {
                Interlocked.Increment(ref callCount);
                return Task.FromResult(payload);
            }
        }

        private sealed class ThrowingHttpRequestMaker : IHttpRequestMaker
        {
            private readonly Exception ex;
            public ThrowingHttpRequestMaker(Exception ex) { this.ex = ex; }

            public Task<byte[]> MakeRequestAsync(Uri uri,
                byte[] postJson = null,
                IEnumerable<KeyValuePair<string, object>> headers = null,
                string method = null,
                CancellationToken cancelToken = default)
            {
                throw ex;
            }
        }

        private sealed class FakeDnsLookup : IDnsLookup
        {
            private readonly Dictionary<string, IPAddress[]> map;
            public bool ThrowSocketHostNotFoundOnUnknown { get; set; }

            public FakeDnsLookup(Dictionary<string, IPAddress[]> map) { this.map = map; }

            public Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress)
            {
                if (map.TryGetValue(hostNameOrAddress, out var addrs))
                {
                    return Task.FromResult(addrs);
                }
                if (ThrowSocketHostNotFoundOnUnknown)
                {
                    throw new System.Net.Sockets.SocketException(
                        (int)System.Net.Sockets.SocketError.HostNotFound);
                }
                return Task.FromResult(Array.Empty<IPAddress>());
            }

            public Task<IPHostEntry> GetHostEntryAsync(string hostNameOrAddress)
                => throw new NotImplementedException();

            public Task<string> GetHostNameAsync(string hostNameOrAddress)
                => throw new NotImplementedException();
        }
    }
}
