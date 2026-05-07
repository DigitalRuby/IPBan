/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

End-to-end tests for the auto-config download channel — IPBanService.GetUrl
(UrlType.Config). The handler downloads bytes from the operator-configured
GetUrlConfig URL and feeds them into WriteConfigAsync, which becomes the live
service config. This is in the same trust class as the auto-update binary
channel: an attacker who controls the config server can rewrite GetUrlUpdate,
ProcessToRunOnBan, etc. Each branch (empty body, valid XML, malformed XML,
HTTP failure) is exercised with a mocked IHttpRequestMaker.
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanConfigChannelTests
    {
        // -------- test doubles --------

        /// <summary>Returns a fixed payload for any URL.</summary>
        private sealed class FakeHttpRequestMaker : IHttpRequestMaker
        {
            public byte[] Payload { get; }
            public List<Uri> Calls { get; } = new();
            public FakeHttpRequestMaker(byte[] payload) { Payload = payload; }

            public Task<byte[]> MakeRequestAsync(Uri uri,
                byte[] postJson = null,
                IEnumerable<KeyValuePair<string, object>> headers = null,
                string method = null,
                CancellationToken cancelToken = default)
            {
                Calls.Add(uri);
                return Task.FromResult(Payload);
            }
        }

        /// <summary>Throws on every request.</summary>
        private sealed class ThrowingHttpRequestMaker : IHttpRequestMaker
        {
            private readonly Exception ex;
            public ThrowingHttpRequestMaker(Exception ex) { this.ex = ex; }
            public Task<byte[]> MakeRequestAsync(Uri uri,
                byte[] postJson = null,
                IEnumerable<KeyValuePair<string, object>> headers = null,
                string method = null,
                CancellationToken cancelToken = default)
                => throw ex;
        }

        /// <summary>
        /// Subclass that records WriteConfigAsync calls and exposes the protected GetUrl method.
        /// We override WriteConfigAsync so we don't actually clobber the test's config file
        /// during the test run.
        /// </summary>
        public sealed class CapturingIPBanService : IPBanService
        {
            public List<string> WrittenConfigs { get; } = new();
            private readonly bool simulateInvalidXmlOnPath;

            public CapturingIPBanService() : this(false) { }
            public CapturingIPBanService(bool simulateInvalidXmlOnPath)
            {
                this.simulateInvalidXmlOnPath = simulateInvalidXmlOnPath;
            }

            public override async Task WriteConfigAsync(string xml)
            {
                // Run the same xml-validation step the production override does, so a malformed
                // body still throws and exercises the catch in GetUrl.
                var doc = new System.Xml.XmlDocument();
                doc.LoadXml(xml);
                WrittenConfigs.Add(xml);
                await Task.CompletedTask;
            }

            public Task<bool> CallGetUrl(UrlType urlType, CancellationToken cancelToken = default)
                => GetUrl(urlType, cancelToken);
        }

        // -------- helpers --------

        private const string TestConfigUrl = "http://localhost/configfeed";

        private static CapturingIPBanService CreateService(string configUrl)
        {
            string line = $"<add key=\"GetUrlConfig\" value=\"{configUrl}\"/>";
            return IPBanServiceTestConfigHelper.CreateServiceWithConfig<CapturingIPBanService>(
                cfg => cfg.Replace("<add key=\"GetUrlConfig\" value=\"\"/>", line));
        }

        // -------- tests --------

        [Test]
        public async Task EmptyResponseBody_DoesNotCallWriteConfigAsync()
        {
            // Server returns 200 with no body. The handler must NOT invoke WriteConfigAsync —
            // there's nothing to write, and an empty XML document would corrupt the config.
            byte[] empty = Array.Empty<byte>();
            var service = CreateService(TestConfigUrl);
            try
            {
                var http = new FakeHttpRequestMaker(empty);
                service.RequestMaker = http;

                bool result = await service.CallGetUrl(IPBanService.UrlType.Config, CancellationToken.None);

                ClassicAssert.IsTrue(result, "GetUrl returns true on success path even for empty body");
                ClassicAssert.AreEqual(1, http.Calls.Count, "the URL should still be fetched once");
                CollectionAssert.IsEmpty(service.WrittenConfigs,
                    "empty body must NOT trigger WriteConfigAsync");
            }
            finally
            {
                service.Dispose();
            }
        }

        [Test]
        public async Task ValidXmlBody_CallsWriteConfigAsyncWithBytes()
        {
            // Happy path — server returns a well-formed config XML and the handler hands it
            // verbatim to WriteConfigAsync.
            const string newConfig =
                "<?xml version=\"1.0\"?><configuration><appSettings>" +
                "<add key=\"BanTime\" value=\"00:30:00\" />" +
                "</appSettings></configuration>";
            byte[] bytes = Encoding.UTF8.GetBytes(newConfig);

            var service = CreateService(TestConfigUrl);
            try
            {
                var http = new FakeHttpRequestMaker(bytes);
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Config, CancellationToken.None);

                ClassicAssert.AreEqual(1, service.WrittenConfigs.Count,
                    "valid XML must be written exactly once");
                ClassicAssert.AreEqual(newConfig, service.WrittenConfigs[0],
                    "the body delivered to WriteConfigAsync must match the bytes verbatim");
            }
            finally
            {
                service.Dispose();
            }
        }

        [Test]
        public async Task MalformedXmlBody_IsCaughtNotRethrown()
        {
            // Server returns garbage that isn't well-formed XML. WriteConfigAsync's xml
            // validation will throw, and the catch in GetUrl must swallow that — a flaky
            // config server can't be allowed to take down the cycle.
            byte[] bytes = Encoding.UTF8.GetBytes("this is not <xml />");

            var service = CreateService(TestConfigUrl);
            try
            {
                var http = new FakeHttpRequestMaker(bytes);
                service.RequestMaker = http;

                Assert.DoesNotThrowAsync(async () =>
                    await service.CallGetUrl(IPBanService.UrlType.Config, CancellationToken.None));

                // WriteConfigAsync was attempted but threw; the captured list reflects that
                // (our override adds to WrittenConfigs only after LoadXml succeeds, so it
                // stays empty when the body is malformed).
                CollectionAssert.IsEmpty(service.WrittenConfigs,
                    "malformed XML must not be persisted");
            }
            finally
            {
                service.Dispose();
            }
        }

        [Test]
        public async Task HttpRequestFailure_IsCaughtNotRethrown()
        {
            // Network failure (DNS, timeout, 5xx) must be caught by GetUrl. A flapping
            // config server should not crash the service.
            var service = CreateService(TestConfigUrl);
            try
            {
                service.RequestMaker = new ThrowingHttpRequestMaker(
                    new TimeoutException("simulated network failure"));

                Assert.DoesNotThrowAsync(async () =>
                    await service.CallGetUrl(IPBanService.UrlType.Config, CancellationToken.None));

                CollectionAssert.IsEmpty(service.WrittenConfigs,
                    "no config write should occur on a failed fetch");
            }
            finally
            {
                service.Dispose();
            }
        }

        [Test]
        public async Task EmptyConfigUrl_NoFetchAttempted()
        {
            // If GetUrlConfig is empty (the default), GetUrl returns true without making
            // any HTTP request. This protects deployments that haven't opted in to remote
            // config from accidentally fetching a configurable-but-unintended URL.
            var service = CreateService(string.Empty);
            try
            {
                var http = new FakeHttpRequestMaker(Array.Empty<byte>());
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Config, CancellationToken.None);

                CollectionAssert.IsEmpty(http.Calls,
                    "an empty GetUrlConfig must not trigger an HTTP request");
                CollectionAssert.IsEmpty(service.WrittenConfigs);
            }
            finally
            {
                service.Dispose();
            }
        }
    }
}
