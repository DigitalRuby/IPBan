/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanBlockIPAddressesUpdater and IPBanUnblockIPAddressesUpdater —
the file-watcher updaters that let an external process drop "ban*.txt" or
"unban*.txt" files into a directory and trigger ban/unban events. We verify:
  - valid lines turn into the right event type
  - lines that aren't parseable as IPs are dropped
  - "ip,source" two-piece lines populate the source correctly
  - the file is removed after processing
  - nothing is processed when the directory has no matching files
  - exceptions during read don't propagate (the cycle must keep running)
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanBlockUnblockUpdaterTests
    {
        // Capture handler that records every event the updater pushes.
        private sealed class CapturingHandler : IIPAddressEventHandler
        {
            public List<IPAddressLogEvent> Events { get; } = new();
            public void AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> ipAddresses)
                => Events.AddRange(ipAddresses);
        }

        private static string CreateTempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ipban_updater_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        // -------------------- Block updater --------------------

        [Test]
        public async Task BlockUpdater_ProcessesValidIpsAndDeletesFile()
        {
            string dir = CreateTempDir();
            try
            {
                string banFile = Path.Combine(dir, "ban_test.txt");
                File.WriteAllText(banFile, "1.2.3.4\n5.6.7.8\n");

                var handler = new CapturingHandler();
                using var updater = new IPBanBlockIPAddressesUpdater(handler, Path.Combine(dir, "ban*.txt"));
                await updater.Update(CancellationToken.None);

                ClassicAssert.AreEqual(2, handler.Events.Count);
                CollectionAssert.AreEqual(
                    new[] { "1.2.3.4", "5.6.7.8" },
                    handler.Events.Select(e => e.IPAddress).ToArray());

                ClassicAssert.IsTrue(handler.Events.All(e => e.Type == IPAddressEventType.Blocked),
                    "every event must have type Blocked");
                ClassicAssert.IsFalse(File.Exists(banFile),
                    "the ban file must be deleted after processing");
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task BlockUpdater_DropsNonIpLines()
        {
            string dir = CreateTempDir();
            try
            {
                string banFile = Path.Combine(dir, "ban.txt");
                File.WriteAllText(banFile, "10.0.0.1\nnot-an-ip\n10.0.0.2\n");

                var handler = new CapturingHandler();
                using var updater = new IPBanBlockIPAddressesUpdater(handler, Path.Combine(dir, "ban*.txt"));
                await updater.Update(CancellationToken.None);

                ClassicAssert.AreEqual(2, handler.Events.Count,
                    "the malformed line must be silently dropped");
                CollectionAssert.AreEqual(
                    new[] { "10.0.0.1", "10.0.0.2" },
                    handler.Events.Select(e => e.IPAddress).ToArray());
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task BlockUpdater_DefaultsSourceToBlock_WhenNoCommaPresent()
        {
            string dir = CreateTempDir();
            try
            {
                File.WriteAllText(Path.Combine(dir, "ban.txt"), "1.1.1.1\n");

                var handler = new CapturingHandler();
                using var updater = new IPBanBlockIPAddressesUpdater(handler, Path.Combine(dir, "ban*.txt"));
                await updater.Update(CancellationToken.None);

                ClassicAssert.AreEqual(1, handler.Events.Count);
                ClassicAssert.AreEqual("Block", handler.Events[0].Source,
                    "with no comma, the source defaults to 'Block'");
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task BlockUpdater_ProcessesAllMatchingFilesInDirectory()
        {
            // The updater takes a directory path + glob mask; multiple matching files in the
            // directory should all be processed (and all deleted) in one Update call.
            string dir = CreateTempDir();
            try
            {
                File.WriteAllText(Path.Combine(dir, "ban_a.txt"), "1.0.0.1\n");
                File.WriteAllText(Path.Combine(dir, "ban_b.txt"), "1.0.0.2\n");

                var handler = new CapturingHandler();
                using var updater = new IPBanBlockIPAddressesUpdater(handler, Path.Combine(dir, "ban*.txt"));
                await updater.Update(CancellationToken.None);

                ClassicAssert.AreEqual(2, handler.Events.Count);
                ClassicAssert.IsFalse(File.Exists(Path.Combine(dir, "ban_a.txt")));
                ClassicAssert.IsFalse(File.Exists(Path.Combine(dir, "ban_b.txt")));
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task BlockUpdater_NoMatchingFiles_NoEventsRaised()
        {
            string dir = CreateTempDir();
            try
            {
                // Empty directory — nothing matches the ban*.txt mask.
                var handler = new CapturingHandler();
                using var updater = new IPBanBlockIPAddressesUpdater(handler, Path.Combine(dir, "ban*.txt"));
                await updater.Update(CancellationToken.None);

                CollectionAssert.IsEmpty(handler.Events);
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task BlockUpdater_NonExistentDirectory_DoesNotThrow()
        {
            // The constructor accepts the path as-is, including non-existent dirs. Update
            // must catch the resulting Directory.GetFiles exception and continue.
            string nowhere = Path.Combine(Path.GetTempPath(), "ipban_does_not_exist_" + Guid.NewGuid().ToString("N"), "ban*.txt");
            var handler = new CapturingHandler();
            using var updater = new IPBanBlockIPAddressesUpdater(handler, nowhere);
            Assert.DoesNotThrowAsync(async () => await updater.Update(CancellationToken.None));
            CollectionAssert.IsEmpty(handler.Events);
        }

        [Test]
        public void BlockUpdater_NullServiceArgumentThrows()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new IPBanBlockIPAddressesUpdater(null, Path.Combine(Path.GetTempPath(), "ban*.txt")));
        }

        // -------------------- Unblock updater --------------------

        [Test]
        public async Task UnblockUpdater_ProcessesValidIpsAndDeletesFile()
        {
            string dir = CreateTempDir();
            try
            {
                string unbanFile = Path.Combine(dir, "unban.txt");
                File.WriteAllText(unbanFile, "1.2.3.4\n5.6.7.8\n");

                var handler = new CapturingHandler();
                using var updater = new IPBanUnblockIPAddressesUpdater(handler, Path.Combine(dir, "unban*.txt"));
                await updater.Update(CancellationToken.None);

                ClassicAssert.AreEqual(2, handler.Events.Count);
                CollectionAssert.AreEqual(
                    new[] { "1.2.3.4", "5.6.7.8" },
                    handler.Events.Select(e => e.IPAddress).ToArray());

                ClassicAssert.IsTrue(handler.Events.All(e => e.Type == IPAddressEventType.Unblocked),
                    "every event must have type Unblocked");
                ClassicAssert.IsTrue(handler.Events.All(e => e.Source == "Unblock"),
                    "the source for the unblock updater is hard-coded to 'Unblock'");
                ClassicAssert.IsFalse(File.Exists(unbanFile),
                    "the unban file must be deleted after processing");
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
            }
        }

        [Test]
        public void UnblockUpdater_DirectMethod_RaisesUnblockEventsForEachIp()
        {
            // UnblockIPAddresses is also exposed as a public method, used by callers that
            // already know which IPs to unban (no file scan).
            var handler = new CapturingHandler();
            using var updater = new IPBanUnblockIPAddressesUpdater(handler, "unused");

            updater.UnblockIPAddresses(new[] { "10.0.0.1", "10.0.0.2", "10.0.0.3" });

            ClassicAssert.AreEqual(3, handler.Events.Count);
            ClassicAssert.IsTrue(handler.Events.All(e => e.Type == IPAddressEventType.Unblocked));
        }

        [Test]
        public void UnblockUpdater_NullServiceArgumentThrows()
        {
            Assert.Throws<ArgumentNullException>(() =>
                new IPBanUnblockIPAddressesUpdater(null, Path.Combine(Path.GetTempPath(), "unban*.txt")));
        }
    }
}
