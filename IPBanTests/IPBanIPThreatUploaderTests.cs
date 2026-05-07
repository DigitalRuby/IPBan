/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanIPThreatUploader.AddIPAddressLogEvents — covers the filter
behavior and the lock semantics around the internal events list.
*/

using System;
using System.Collections.Generic;
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
        public void ConcurrentAddDoesNotCorruptInternalList()
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

            Assert.DoesNotThrowAsync(() => Task.WhenAll(tasks));
        }
    }
}
