/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanIPThreatUploader (C3 — `lock(events)` was locking the parameter
not the field, leaving `this.events` mutation racy with Update()).
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

        [SetUp]
        public void Setup()
        {
            IPBanService.UtcNow = DateTime.UtcNow;
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            uploader = new IPBanIPThreatUploader(service);
        }

        [TearDown]
        public void Teardown()
        {
            uploader?.Dispose();
            IPBanService.DisposeIPBanTestService(service);
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
            // C3 regression test: pre-fix `lock(events)` locked the *parameter* (the
            // IEnumerable passed in), so concurrent callers each held a different lock and
            // mutated `this.events` in parallel. With the fix locking `this.events`, this
            // runs cleanly. Pre-fix this would intermittently throw InvalidOperationException
            // ("Collection was modified") from List<T> growth races, or duplicate/lose events.
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
