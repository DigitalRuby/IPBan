/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for LogFileScanner.NormalizeGlob - the glob parsing helper
that splits a path/mask into directory + escaped glob portions.
*/

using System;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanLogFileScannerNormalizeGlobTests
    {
        [Test]
        public void NormalizeGlob_NullOrEmpty_ReturnsAsIs()
        {
            var result = LogFileScanner.NormalizeGlob(null, out var dir, out var glob);
            ClassicAssert.IsNull(result);
            ClassicAssert.IsNull(dir);
            ClassicAssert.IsNull(glob);

            result = LogFileScanner.NormalizeGlob("", out dir, out glob);
            ClassicAssert.AreEqual("", result);
            ClassicAssert.IsNull(dir);
            ClassicAssert.IsNull(glob);
        }

        [Test]
        public void NormalizeGlob_DbPrefix_PassThrough()
        {
            var r = LogFileScanner.NormalizeGlob("db:something", out _, out _);
            ClassicAssert.AreEqual("db:something", r);
        }

        [Test]
        public void NormalizeGlob_WithWildcardPattern()
        {
            string normalized = LogFileScanner.NormalizeGlob("/var/log/*.log", out var dir, out var glob);
            ClassicAssert.AreEqual("/var/log/", dir);
            ClassicAssert.AreEqual("*.log", glob);
            StringAssert.Contains("*.log", normalized);
        }

        [Test]
        public void NormalizeGlob_BackslashesConvertedToForwardSlash()
        {
            string normalized = LogFileScanner.NormalizeGlob(@"C:\Logs\*.log", out var dir, out var glob);
            ClassicAssert.AreEqual("C:/Logs/", dir);
            ClassicAssert.AreEqual("*.log", glob);
        }

        [Test]
        public void NormalizeGlob_NoWildcard_DirAndFile()
        {
            string normalized = LogFileScanner.NormalizeGlob("/var/log/file.log", out var dir, out var glob);
            ClassicAssert.AreEqual("/var/log/", dir);
            ClassicAssert.AreEqual("file.log", glob);
        }

        [Test]
        public void NormalizeGlob_TrailingSlash_Throws()
        {
            // No file segment after the trailing slash.
            Assert.Throws<ArgumentException>(() =>
                LogFileScanner.NormalizeGlob("/var/log/", out _, out _));
        }

        [Test]
        public void NormalizeGlob_NoDirSeparator_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                LogFileScanner.NormalizeGlob("abc.log", out _, out _));
        }

        [Test]
        public void NormalizeGlob_EscapesParens_AndBrackets()
        {
            string normalized = LogFileScanner.NormalizeGlob("/var/log/(file)*.log", out var dir, out var glob);
            ClassicAssert.AreEqual("/var/log/", dir);
            // Unescaped chars get \ prefix in glob
            StringAssert.Contains("\\(", glob);
            StringAssert.Contains("\\)", glob);
        }
    }

    // -------------------- LogFileScanner instance methods --------------------

    [TestFixture]
    public sealed class IPBanLogFileScannerInstanceTests
    {
        private string tempDir;

        [SetUp]
        public void SetUp()
        {
            tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ipban_lfsi_" + System.Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(tempDir);
        }

        [TearDown]
        public void TearDown()
        {
            try { System.IO.Directory.Delete(tempDir, true); } catch { /* best effort */ }
        }

        [Test]
        public void Construct_NullPath_Throws()
        {
            Assert.Throws<System.ArgumentNullException>(() =>
                _ = new LogFileScanner(null));
        }

        [Test]
        public void Construct_BasicInstance_HasPathAndMask()
        {
            using var scanner = new LogFileScanner(System.IO.Path.Combine(tempDir, "*.log"));
            ClassicAssert.AreEqual(System.IO.Path.Combine(tempDir, "*.log"), scanner.PathAndMask);
        }

        [Test]
        public void ToString_ContainsPathAndMask()
        {
            using var scanner = new LogFileScanner(System.IO.Path.Combine(tempDir, "*.log"));
            // The implementation prefixes with "Path/Mask: ", so check containment.
            StringAssert.Contains(scanner.PathAndMask, scanner.ToString());
        }

        [Test]
        public void MatchesOptions_DefaultBaseImpl_ReturnsFalse()
        {
            using var scanner = new LogFileScanner(System.IO.Path.Combine(tempDir, "*.log"));
            // Default base implementation always returns false
            ClassicAssert.IsFalse(scanner.MatchesOptions(default));
        }

        [Test]
        public void Update_OnExistingFile_CallsProcessText()
        {
            // Create a file, attach a processText callback, run Update.
            string path = System.IO.Path.Combine(tempDir, "log.log");
            System.IO.File.WriteAllText(path, "line one\nline two\n");
            int linesSeen = 0;
            using var scanner = new LogFileScanner(System.IO.Path.Combine(tempDir, "*.log"),
                startAtBeginning: true,
                processText: text => linesSeen += text.Split('\n').Length);
            scanner.Update();
            ClassicAssert.GreaterOrEqual(linesSeen, 1);
        }

        [Test]
        public void Update_OnEmptyDir_DoesNotThrow()
        {
            using var scanner = new LogFileScanner(System.IO.Path.Combine(tempDir, "*.log"));
            scanner.Update();
        }

        [Test]
        public void GetFiles_OnEmptyDir_ReturnsEmpty()
        {
            var files = LogFileScanner.GetFiles(System.IO.Path.Combine(tempDir, "*.log"));
            CollectionAssert.IsEmpty(files);
        }

        [Test]
        public void GetFiles_WithExistingFiles_ReturnsThem()
        {
            string path = System.IO.Path.Combine(tempDir, "a.log");
            System.IO.File.WriteAllText(path, "x");
            var files = LogFileScanner.GetFiles(System.IO.Path.Combine(tempDir, "*.log"), startAtBeginning: true);
            ClassicAssert.GreaterOrEqual(files.Count, 1);
        }

        [Test]
        public void WatchedFile_Equals_ByFileName()
        {
            var f1 = new LogFileScanner.WatchedFile("/a/b.log");
            var f2 = new LogFileScanner.WatchedFile("/a/b.log");
            var f3 = new LogFileScanner.WatchedFile("/a/c.log");
            ClassicAssert.IsTrue(f1.Equals(f2));
            ClassicAssert.IsFalse(f1.Equals(f3));
            ClassicAssert.IsFalse(f1.Equals("not a file"));
            ClassicAssert.AreEqual(f1.GetHashCode(), f2.GetHashCode());
        }

        [Test]
        public void Replay_WithCancellation_StopsCleanly()
        {
            string src = System.IO.Path.Combine(tempDir, "src.log");
            string dst = System.IO.Path.Combine(tempDir, "dst.log");
            System.IO.File.WriteAllText(src, new string('a', 256));
            using var cts = new System.Threading.CancellationTokenSource();
            cts.Cancel();
            // Cancellation token already triggered, so the loop exits immediately.
            Assert.DoesNotThrow(() => LogFileScanner.Replay(src, dst, delay: 0, cancelToken: cts.Token));
            ClassicAssert.IsTrue(System.IO.File.Exists(dst));
        }
    }
}
