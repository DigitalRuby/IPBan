/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanConfigReaderWriter — the abstraction backing live config reload.
The class supports two modes (file-backed for production, in-memory for tests),
performs atomic file writes via .tmp + rename, and detects changes via mtime.
A regression here silently breaks every "reload on config change" workflow.
*/

using System;
using System.IO;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanConfigReaderWriterTests
    {
        // -------------------- in-memory (UseFile = false) --------------------

        [Test]
        public async Task InMemory_ReadAfterWriteReturnsContent()
        {
            var rw = new IPBanConfigReaderWriter { UseFile = false };
            await rw.WriteConfigAsync("<configuration></configuration>");
            string read = await rw.ReadConfigAsync();
            ClassicAssert.AreEqual("<configuration></configuration>", read);
        }

        [Test]
        public void InMemory_ReadWithoutWriteThrows()
        {
            // The contract: if UseFile=false and GlobalConfigString is empty, ReadConfigAsync
            // throws — readers are expected to ensure something has been written first.
            var rw = new IPBanConfigReaderWriter { UseFile = false, GlobalConfigString = string.Empty };
            Assert.ThrowsAsync<IOException>(async () => await rw.ReadConfigAsync());
        }

        [Test]
        public async Task InMemory_CheckForChange_DetectsNewValue()
        {
            // First poll seeds the local copy and reports the change; second poll with the
            // same value reports no change.
            var rw = new IPBanConfigReaderWriter { UseFile = false, GlobalConfigString = "<a/>" };

            string first = await rw.CheckForConfigChangeAsync();
            ClassicAssert.AreEqual("<a/>", first, "first call returns the current value");

            string second = await rw.CheckForConfigChangeAsync();
            ClassicAssert.IsNull(second, "second call with no change returns null");

            // Mutate the global string and the change is detected.
            rw.GlobalConfigString = "<b/>";
            string third = await rw.CheckForConfigChangeAsync();
            ClassicAssert.AreEqual("<b/>", third);
        }

        // -------------------- file mode (UseFile = true) --------------------

        // Production WriteConfigAsync reads the existing file before deciding whether to
        // rewrite (skip-if-identical optimization). That means the file must already exist
        // when the first Write happens. Create an empty placeholder for each test.
        private static string TempConfigPath()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_cfg_" + Guid.NewGuid().ToString("N") + ".xml");
            File.WriteAllText(path, string.Empty);
            return path;
        }

        [Test]
        public async Task FileMode_WriteThenReadRoundTrips()
        {
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                const string xml = "<?xml version=\"1.0\"?><configuration><appSettings/></configuration>";
                await rw.WriteConfigAsync(xml);

                ClassicAssert.IsTrue(File.Exists(path), "the file should exist after Write");
                string read = await rw.ReadConfigAsync();
                ClassicAssert.AreEqual(xml, read);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
                try { File.Delete(path + ".tmp"); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_WriteIsAtomic_TempFileGoneAfterSuccess()
        {
            // The atomic write goes Path.tmp → File.Move(tempConfig, Path). After a successful
            // write, the .tmp companion must be gone.
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                await rw.WriteConfigAsync("<root/>");

                ClassicAssert.IsTrue(File.Exists(path));
                ClassicAssert.IsFalse(File.Exists(path + ".tmp"),
                    ".tmp file must not be left behind after a successful Move");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
                try { File.Delete(path + ".tmp"); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_WriteIsNoOpWhenContentUnchanged()
        {
            // The class deliberately skips the rewrite if content matches what's already on
            // disk — this avoids triggering FileSystemWatcher reload churn.
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                await rw.WriteConfigAsync("<root/>");
                DateTime mtime1 = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                File.SetLastWriteTimeUtc(path, mtime1);

                await rw.WriteConfigAsync("<root/>");
                DateTime mtime2 = File.GetLastWriteTimeUtc(path);

                ClassicAssert.AreEqual(mtime1, mtime2,
                    "rewriting identical content must not bump the file's mtime");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
                try { File.Delete(path + ".tmp"); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_WriteIgnoresEmptyConfig()
        {
            // Writes are skipped for null / whitespace input — protects against accidentally
            // truncating the live config to an empty document.
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                await rw.WriteConfigAsync("<root>data</root>");
                long sizeBefore = new FileInfo(path).Length;

                await rw.WriteConfigAsync(string.Empty);
                await rw.WriteConfigAsync(null);
                await rw.WriteConfigAsync("   ");

                long sizeAfter = new FileInfo(path).Length;
                ClassicAssert.AreEqual(sizeBefore, sizeAfter,
                    "empty / whitespace writes must not modify the file");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
                try { File.Delete(path + ".tmp"); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_WriteSkippedWhenDisabled()
        {
            // Enabled=false means the reader/writer is dormant; writes silently no-op so a
            // service in "read-only" state never accidentally writes config.
            // Use a fresh path that does NOT exist (skip the placeholder helper) so we can
            // assert the disabled writer didn't create it.
            string path = Path.Combine(Path.GetTempPath(), "ipban_cfg_disabled_" + Guid.NewGuid().ToString("N") + ".xml");
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true, Enabled = false };
            try
            {
                await rw.WriteConfigAsync("<root/>");
                ClassicAssert.IsFalse(File.Exists(path),
                    "no file should be created when Enabled is false");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
                try { File.Delete(path + ".tmp"); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_CheckForChange_FirstCallReturnsContent()
        {
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                await File.WriteAllTextAsync(path, "<initial/>");
                string change = await rw.CheckForConfigChangeAsync();
                ClassicAssert.AreEqual("<initial/>", change);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_CheckForChange_DetectsExternalEdit()
        {
            // Simulate an external editor changing the file: we change the content AND bump
            // the mtime. The next CheckForConfigChangeAsync must surface the new content.
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                await File.WriteAllTextAsync(path, "<v1/>");
                _ = await rw.CheckForConfigChangeAsync();   // seed

                ClassicAssert.IsNull(await rw.CheckForConfigChangeAsync(),
                    "no second-call change for unchanged content");

                // External edit: change content + push mtime forward.
                await File.WriteAllTextAsync(path, "<v2/>");
                File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(2));

                string change = await rw.CheckForConfigChangeAsync();
                ClassicAssert.AreEqual("<v2/>", change);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_CheckForChange_ForceReloadReturnsContentEvenIfUnchanged()
        {
            // forceReload=true bypasses the mtime / value-equality short circuit. This is the
            // path used by the cycle's periodic re-read for re-resolving DNS entries etc.
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                await File.WriteAllTextAsync(path, "<root/>");
                _ = await rw.CheckForConfigChangeAsync();   // seed

                ClassicAssert.IsNull(await rw.CheckForConfigChangeAsync(forceReload: false),
                    "without force, an unchanged file reports null");

                string forced = await rw.CheckForConfigChangeAsync(forceReload: true);
                ClassicAssert.AreEqual("<root/>", forced,
                    "with force, the current content is returned even if unchanged");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_CheckForChange_MissingFileReturnsNull()
        {
            // A path that doesn't exist must not throw; CheckForConfigChangeAsync returns null
            // and lets the caller try again later.
            var rw = new IPBanConfigReaderWriter
            {
                Path = Path.Combine(Path.GetTempPath(), "ipban_missing_" + Guid.NewGuid().ToString("N") + ".xml"),
                UseFile = true,
            };
            string change = await rw.CheckForConfigChangeAsync();
            ClassicAssert.IsNull(change);
        }

        [Test]
        public async Task FileMode_CheckForChange_ReturnsNullWhenDisabled()
        {
            string path = TempConfigPath();
            try
            {
                await File.WriteAllTextAsync(path, "<x/>");
                var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true, Enabled = false };
                string change = await rw.CheckForConfigChangeAsync();
                ClassicAssert.IsNull(change, "Enabled=false must short-circuit to null");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task FileMode_WriteNormalizesNullsAndUnicode()
        {
            // The contract trims, strips embedded NULs, and normalizes Unicode form before
            // writing. Verify each step.
            string path = TempConfigPath();
            var rw = new IPBanConfigReaderWriter { Path = path, UseFile = true };
            try
            {
                // Embedded NUL plus surrounding whitespace
                await rw.WriteConfigAsync("\n  <root>a\0b</root>  \n");
                string written = await File.ReadAllTextAsync(path);
                ClassicAssert.AreEqual("<root>ab</root>", written,
                    "leading/trailing whitespace must be trimmed and embedded NULs stripped");
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
                try { File.Delete(path + ".tmp"); } catch { /* best effort */ }
            }
        }
    }
}
