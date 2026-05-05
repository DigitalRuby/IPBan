/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for the auto-update channel (C1 — verify a SHA-256 hash of the downloaded
binary against the operator-configured `GetUrlUpdateSha256` before executing it).
*/

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// End-to-end tests for IPBanService.GetUrl(UrlType.Update):
    ///   - empty config hash → binary fetched but NOT executed (safe default)
    ///   - mismatched hash    → binary rejected, NOT executed
    ///   - matching hash      → binary executed
    ///
    /// We swap in a fake IHttpRequestMaker so no real network traffic flies, and we
    /// subclass IPBanService to override LaunchUpdateBinary so no real subprocess starts.
    /// </summary>
    [TestFixture]
    public sealed class IPBanUpdateChannelTests
    {
        // -------- test doubles --------

        /// <summary>Captures-and-returns a fixed payload for any URL.</summary>
        private sealed class FakeHttpRequestMaker : IHttpRequestMaker
        {
            public byte[] Payload { get; }
            public List<Uri> Calls { get; } = [];

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

        /// <summary>Subclass that records LaunchUpdateBinary calls and exposes GetUrl.</summary>
        public sealed class CapturingIPBanService : IPBanService
        {
            public List<(string TempFile, string Args)> LaunchedBinaries { get; } = [];

            protected override void LaunchUpdateBinary(string tempFile, string args)
            {
                // intentionally do NOT call base — we don't want to spawn anything in tests
                LaunchedBinaries.Add((tempFile, args));
            }

            public Task<bool> CallGetUrl(UrlType urlType, CancellationToken cancelToken = default)
                => GetUrl(urlType, cancelToken);
        }

        // -------- helpers --------

        private const string TestUpdateUrl = "http://localhost/update";

        private static string Sha256Hex(byte[] bytes) =>
            Convert.ToHexString(SHA256.HashData(bytes));

        private static CapturingIPBanService CreateService(string updateUrl, string sha256Hash)
        {
            // ipban.config has `<add key="GetUrlUpdate" value=""/>` — no spaces before /> .
            string updateLine = "<add key=\"GetUrlUpdate\" value=\"" + updateUrl + "\"/>";
            string hashLine = string.IsNullOrEmpty(sha256Hash)
                ? string.Empty
                : "\n\t\t<add key=\"GetUrlUpdateSha256\" value=\"" + sha256Hash + "\"/>";

            var svc = IPBanService.CreateAndStartIPBanTestService<CapturingIPBanService>(
                configFileModifier: cfg => cfg.Replace(
                    "<add key=\"GetUrlUpdate\" value=\"\"/>",
                    updateLine + hashLine));

            // GetUrl short-circuits if LocalIPAddressString or FQDN is missing — make sure they're set
            // so the test reaches the hash-verification logic regardless of the host environment.
            if (string.IsNullOrWhiteSpace(svc.LocalIPAddressString))
            {
                svc.LocalIPAddressString = "127.0.0.1";
            }
            return svc;
        }

        // -------- the actual tests --------

        [Test]
        public async Task EmptyHashConfig_FetchesButDoesNotExecute()
        {
            // safe default: if the operator has not opted in by setting GetUrlUpdateSha256,
            // we fetch the bytes (so the operator can inspect them) but do NOT exec them.
            byte[] payload = Encoding.UTF8.GetBytes("fake-update-binary");
            var service = CreateService(TestUpdateUrl, sha256Hash: string.Empty);
            try
            {
                var http = new FakeHttpRequestMaker(payload);
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Update, CancellationToken.None);

                ClassicAssert.AreEqual(1, http.Calls.Count, "should have fetched once");
                CollectionAssert.IsEmpty(service.LaunchedBinaries,
                    "must NOT execute when no hash is configured (safe default)");
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }

        [Test]
        public async Task WrongHash_FetchesButRejects()
        {
            // hash mismatch must reject the binary, log an error, and NOT execute it.
            byte[] payload = Encoding.UTF8.GetBytes("fake-update-binary");
            string wrongHash = new string('0', 64); // 64 hex chars — definitely not the real hash
            var service = CreateService(TestUpdateUrl, sha256Hash: wrongHash);
            try
            {
                var http = new FakeHttpRequestMaker(payload);
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Update, CancellationToken.None);

                ClassicAssert.AreEqual(1, http.Calls.Count);
                CollectionAssert.IsEmpty(service.LaunchedBinaries,
                    "must NOT execute when the configured hash does not match the payload");
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }

        [Test]
        public async Task MatchingHash_ExecutesTheBinary()
        {
            // the happy path — operator configured the correct hash, the bytes match, exec proceeds.
            byte[] payload = Encoding.UTF8.GetBytes("fake-update-binary-v2");
            string correctHash = Sha256Hex(payload);
            var service = CreateService(TestUpdateUrl, sha256Hash: correctHash);
            try
            {
                var http = new FakeHttpRequestMaker(payload);
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Update, CancellationToken.None);

                ClassicAssert.AreEqual(1, http.Calls.Count);
                ClassicAssert.AreEqual(1, service.LaunchedBinaries.Count,
                    "matching hash must execute the binary exactly once");
                StringAssert.EndsWith("IPBanServiceUpdate.exe",
                    service.LaunchedBinaries[0].TempFile);
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }

        [Test]
        public async Task HashCompareIsCaseInsensitive()
        {
            // SHA-256 hex is conventionally either case; the gate must accept both.
            byte[] payload = Encoding.UTF8.GetBytes("test-bytes");
            string lowerHash = Sha256Hex(payload).ToLowerInvariant();
            var service = CreateService(TestUpdateUrl, sha256Hash: lowerHash);
            try
            {
                var http = new FakeHttpRequestMaker(payload);
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Update, CancellationToken.None);

                ClassicAssert.AreEqual(1, service.LaunchedBinaries.Count,
                    "lowercase hex must compare equal to uppercase output of HashData");
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }

        [Test]
        public async Task EmptyResponseBody_NoExecution()
        {
            // server returns nothing — there's no binary to execute regardless of hash config.
            byte[] payload = [];
            var service = CreateService(TestUpdateUrl, sha256Hash: Sha256Hex(payload));
            try
            {
                var http = new FakeHttpRequestMaker(payload);
                service.RequestMaker = http;

                await service.CallGetUrl(IPBanService.UrlType.Update, CancellationToken.None);

                CollectionAssert.IsEmpty(service.LaunchedBinaries,
                    "empty response must never trigger an execution");
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }
    }

    /// <summary>
    /// Lightweight tests for the new <see cref="IPBanConfig.GetUrlUpdateSha256"/> setting.
    /// </summary>
    [TestFixture]
    public sealed class IPBanConfigSha256Tests
    {
        [Test]
        public void DefaultIsEmptyString()
        {
            // default config has no auto-update hash → safe-by-default (binary not executed)
            var service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            try
            {
                ClassicAssert.IsNotNull(service.Config.GetUrlUpdateSha256);
                ClassicAssert.AreEqual(string.Empty, service.Config.GetUrlUpdateSha256);
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }

        [Test]
        public void ConfigValueRoundTrips()
        {
            // when the operator sets GetUrlUpdateSha256 in config, the property exposes that exact value
            const string expectedHash = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
            var service = IPBanService.CreateAndStartIPBanTestService<IPBanService>(
                configFileModifier: cfg => cfg.Replace(
                    "<add key=\"GetUrlUpdate\" value=\"\"/>",
                    "<add key=\"GetUrlUpdate\" value=\"\"/>\n\t\t<add key=\"GetUrlUpdateSha256\" value=\"" + expectedHash + "\"/>"));
            try
            {
                ClassicAssert.AreEqual(expectedHash, service.Config.GetUrlUpdateSha256);
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }
    }
}
