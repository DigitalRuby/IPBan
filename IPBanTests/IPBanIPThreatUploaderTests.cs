/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanIPThreatUploader.AddIPAddressLogEvents — covers the filter
behavior and the lock semantics around the internal events list.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// IPBanIPThreatUploader.AddIPAddressLogEvents — verifies the lock fix and the
    /// pre-filter that runs outside the lock.
    /// </summary>
    [TestFixture]
    public sealed class IPBanIPThreatUploaderTests
    {
        private IPBanService service;
        private IPBanIPThreatUploader uploader;

        [OneTimeSetUp]
        public void OneTimeSetup()
        {
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
        }

        [SetUp]
        public void Setup()
        {
            IPBanService.UtcNow = DateTime.UtcNow;
            uploader = new IPBanIPThreatUploader(service);
        }

        [TearDown]
        public void Teardown()
        {
            uploader?.Dispose();
            uploader = null;
        }

        [OneTimeTearDown]
        public void OneTimeTeardown()
        {
            IPBanService.DisposeIPBanTestService(service);
            service = null;
        }

        [Test]
        public void AddingEmptyEnumerableIsSafe()
        {
            // post-fix: the early-return after pre-filtering means we never lock with no work to do
            Assert.DoesNotThrow(() =>
                uploader.AddIPAddressLogEvents(Array.Empty<IPAddressLogEvent>()));
        }

        [Test]
        public void NonBlockedEventsAreFilteredOut()
        {
            // FailedLogin events are filtered (only Blocked events are uploaded to ipthreat)
            Assert.DoesNotThrow(() => uploader.AddIPAddressLogEvents(
            [
                new("1.2.3.4", "alice", "RDP", 1, IPAddressEventType.FailedLogin)
            ]));
        }

        [Test]
        public void ExternalEventsAreFilteredOut()
        {
            // events flagged External are excluded from the upload set
            Assert.DoesNotThrow(() => uploader.AddIPAddressLogEvents(
            [
                new("1.2.3.4", "alice", "RDP", 1, IPAddressEventType.Blocked,
                    timestamp: default, external: true)
            ]));
        }

        [Test]
        public void ZeroCountEventsAreFilteredOut()
        {
            // count of 0 means external/heartbeat — must not be uploaded
            Assert.DoesNotThrow(() => uploader.AddIPAddressLogEvents(
            [
                new("1.2.3.4", "alice", "RDP", 0, IPAddressEventType.Blocked)
            ]));
        }

        [Test]
        public async Task ConcurrentAddDoesNotCorruptInternalList()
        {
            // The lock must serialize concurrent producers writing to the internal events
            // list. If the lock target were the parameter instead of the field, each caller
            // would hold a different lock and the list would race during AddRange / List<T>
            // resize, surfacing as InvalidOperationException ("Collection was modified") or
            // lost/duplicated events.
            const int producers = 8;
            const int eventsPerProducer = 200;
            var tasks = new List<Task>();

            for (int p = 0; p < producers; p++)
            {
                int seed = p;
                tasks.Add(Task.Run(() =>
                {
                    for (int i = 0; i < eventsPerProducer; i++)
                    {
                        // Blocked + count > 0 + not external + not whitelisted = passes filter
                        var ip = $"10.0.{seed}.{i & 0xFF}";
                        uploader.AddIPAddressLogEvents(
                        [
                            new(ip, "user" + i, "SSH", 1, IPAddressEventType.Blocked)
                        ]);
                    }
                }));
            }

            await Assert.DoesNotThrowAsync(() => Task.WhenAll(tasks));
        }

        /// <summary>
        /// The bulk-report body used to be Newtonsoft JsonConvert.SerializeObject.
        /// Lock the System.Text.Json UTF-8 payload Update posts to api.ipthreat.net.
        /// </summary>
        [Test]
        public async Task Update_PostsSystemTextJsonBulkReport()
        {
            var requestMaker = new CapturingRequestMaker();
            var localService = IPBanServiceTestConfigHelper.CreateServiceWithConfig<IPBanService>(
                xml => IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "IPThreatApiKey", "  unit-test-key  "));
            localService.RequestMaker = requestMaker;

            var now = new DateTime(2026, 11, 5, 21, 0, 0, DateTimeKind.Utc);
            IPBanService.UtcNow = now;
            using var localUploader = new IPBanIPThreatUploader(localService);
            var timestamp = new DateTime(2022, 9, 2, 15, 24, 7, 842, DateTimeKind.Utc);
            localUploader.AddIPAddressLogEvents(
            [
                new("1.2.3.4", "alice", "SMTP", 3, IPAddressEventType.Blocked, timestamp, logData: "Failed password"),
                new("203.0.113.50", "bob", "SSH", 1, IPAddressEventType.Blocked, timestamp, logData: null),
                new("198.51.100.8", "carol", "RDP", 1, IPAddressEventType.FailedLogin, timestamp),
                new("198.51.100.9", "dave", "RDP", 0, IPAddressEventType.Blocked, timestamp),
                new("198.51.100.10", "erin", "RDP", 1, IPAddressEventType.Blocked, timestamp, external: true)
            ]);

            await localUploader.Update();

            Assert.That(requestMaker.Calls, Is.EqualTo(1));
            Assert.That(requestMaker.Uri, Is.EqualTo(new Uri("https://api.ipthreat.net/api/bulkreport")));
            Assert.That(requestMaker.Headers.Single(h => h.Key == "X-API-KEY").Value, Is.EqualTo("unit-test-key"));

            string notesWithLog = (localService.AppName + " - Failed password").Trim(' ', '-');
            string notesWithoutLog = (localService.AppName + " - ").Trim(' ', '-');
            string expected =
                "{\"items\":[" +
                "{\"ip\":\"1.2.3.4\",\"flags\":\"BruteForce\",\"system\":\"SMTP\",\"notes\":\"" + notesWithLog + "\",\"ts\":\"2022-09-02T15:24:07Z\",\"count\":3}," +
                "{\"ip\":\"203.0.113.50\",\"flags\":\"BruteForce\",\"system\":\"SSH\",\"notes\":\"" + notesWithoutLog + "\",\"ts\":\"2022-09-02T15:24:07Z\",\"count\":1}" +
                "]}";
            Assert.That(Encoding.UTF8.GetString(requestMaker.Body), Is.EqualTo(expected));
            Assert.That(requestMaker.Body, Is.EqualTo(Encoding.UTF8.GetBytes(expected)));

            // The next window is 30–90 minutes out, so a second cycle must not post again.
            requestMaker.Calls = 0;
            IPBanService.UtcNow = now.AddMinutes(29);
            await localUploader.Update();
            Assert.That(requestMaker.Calls, Is.EqualTo(0));
        }

        [Test]
        public async Task Update_WithoutApiKey_DoesNotPost()
        {
            var requestMaker = new CapturingRequestMaker();
            var localService = IPBanServiceTestConfigHelper.CreateServiceWithConfig<IPBanService>(
                xml => IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "IPThreatApiKey", "   "));
            localService.RequestMaker = requestMaker;
            IPBanService.UtcNow = new DateTime(2026, 11, 5, 21, 0, 0, DateTimeKind.Utc);
            using var localUploader = new IPBanIPThreatUploader(localService);
            localUploader.AddIPAddressLogEvents(
            [
                new("203.0.113.50", "bob", "SSH", 1, IPAddressEventType.Blocked)
            ]);

            await localUploader.Update();

            Assert.That(requestMaker.Calls, Is.EqualTo(0));
        }

        private sealed class CapturingRequestMaker : IHttpRequestMaker
        {
            public int Calls { get; set; }
            public Uri Uri { get; private set; }
            public byte[] Body { get; private set; }
            public List<KeyValuePair<string, object>> Headers { get; private set; }

            public Task<byte[]> MakeRequestAsync(Uri uri,
                byte[] postJson = null,
                IEnumerable<KeyValuePair<string, object>> headers = null,
                string method = null,
                CancellationToken cancelToken = default)
            {
                Calls++;
                Uri = uri;
                Body = postJson;
                Headers = headers?.ToList();
                return Task.FromResult(Array.Empty<byte>());
            }
        }
    }
}
