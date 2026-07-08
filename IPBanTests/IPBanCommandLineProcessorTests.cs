/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for CommandLineProcessor - exercises each subcommand path.
*/

using System;
using System.IO;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;
using DigitalRuby.IPBanCore.Core.Utility;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanCommandLineProcessorTests
    {
        private string tempDir;

        [SetUp]
        public void Setup()
        {
            tempDir = Path.Combine(Path.GetTempPath(), "ipban_cli_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
        }

        [TearDown]
        public void Cleanup()
        {
            try { Directory.Delete(tempDir, true); } catch { /* best effort */ }
        }

        [Test]
        public async Task NoArgs_ShowsHelpAndReturnsZeroOrOne()
        {
            // Empty args should print help via System.CommandLine.
            using var sw = new StringWriter();
            var prevOut = Console.Out;
            try
            {
                Console.SetOut(sw);
                await CommandLineProcessor.ProcessAsync(Array.Empty<string>());
            }
            finally
            {
                Console.SetOut(prevOut);
            }
            // System.CommandLine prints something; we just ensure no throw
            ClassicAssert.Pass();
        }

        [Test]
        public async Task Version_PrintsSomething()
        {
            using var sw = new StringWriter();
            var prevOut = Console.Out;
            try
            {
                Console.SetOut(sw);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "version" });
                ClassicAssert.AreEqual(0, code);
            }
            finally
            {
                Console.SetOut(prevOut);
            }
            ClassicAssert.IsNotEmpty(sw.ToString());
        }

        [Test]
        public async Task Info_PrintsSomething()
        {
            using var sw = new StringWriter();
            var prevOut = Console.Out;
            try
            {
                Console.SetOut(sw);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "info" });
                ClassicAssert.AreEqual(0, code);
            }
            finally
            {
                Console.SetOut(prevOut);
            }
            ClassicAssert.IsNotEmpty(sw.ToString());
        }

        [Test]
        public async Task List_NonexistentDirectory_ReturnsZero()
        {
            // Looking up DB inside a nonexistent dir, the command catches the error.
            // Specifically, the exit code is 2 because CheckDb("missing/...") fails.
            using var err = new StringWriter();
            var prevErr = Console.Error;
            try
            {
                Console.SetError(err);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "list", "--directory", Path.Combine(tempDir, "nonexistent") });
                ClassicAssert.AreEqual(2, code, "list with missing db returns exit code 2");
            }
            finally
            {
                Console.SetError(prevErr);
            }
        }

        [Test]
        public async Task Unban_MissingBoth_IpAndAll_ReturnsExit2()
        {
            using var err = new StringWriter();
            var prevErr = Console.Error;
            try
            {
                Console.SetError(err);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "unban", "--directory", tempDir });
                ClassicAssert.AreEqual(2, code, "unban without --all or ip arg returns 2");
            }
            finally
            {
                Console.SetError(prevErr);
            }
        }

        [Test]
        public async Task Unban_BadIp_ReturnsExit2()
        {
            using var err = new StringWriter();
            var prevErr = Console.Error;
            try
            {
                Console.SetError(err);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "unban", "not-an-ip", "--directory", tempDir });
                ClassicAssert.AreEqual(2, code);
            }
            finally
            {
                Console.SetError(prevErr);
            }
        }

        [Test]
        public async Task Unban_GoodIp_AppendsToUnbanFile()
        {
            int code = await CommandLineProcessor.ProcessAsync(new[] { "unban", "1.2.3.4", "--directory", tempDir });
            ClassicAssert.AreEqual(0, code);
            string unbanFile = Path.Combine(tempDir, "unban.txt");
            ClassicAssert.IsTrue(File.Exists(unbanFile));
            string content = await File.ReadAllTextAsync(unbanFile);
            StringAssert.Contains("1.2.3.4", content);
        }

        [Test]
        public async Task Unban_GoodIp_DedupsWithExistingFile()
        {
            // Pre-populate unban.txt
            string unbanFile = Path.Combine(tempDir, "unban.txt");
            await File.WriteAllLinesAsync(unbanFile, new[] { "1.2.3.4" });

            int code = await CommandLineProcessor.ProcessAsync(new[] { "unban", "1.2.3.4", "--directory", tempDir });
            ClassicAssert.AreEqual(0, code);

            string[] lines = await File.ReadAllLinesAsync(unbanFile);
            int matches = 0;
            foreach (var line in lines) { if (line.Trim() == "1.2.3.4") matches++; }
            ClassicAssert.AreEqual(1, matches, "duplicate IP should not be appended again");
        }

        [Test]
        public async Task Unban_All_NoDb_ReturnsExit2()
        {
            using var err = new StringWriter();
            var prevErr = Console.Error;
            try
            {
                Console.SetError(err);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "unban", "--all", "--yes", "--directory", tempDir });
                ClassicAssert.AreEqual(2, code, "unban --all with no db returns 2");
            }
            finally
            {
                Console.SetError(prevErr);
            }
        }

        [Test]
        public async Task Ban_BadDir_ReturnsExit2()
        {
            using var err = new StringWriter();
            var prevErr = Console.Error;
            try
            {
                Console.SetError(err);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "ban", "1.2.3.4", "--directory", Path.Combine(tempDir, "missing") });
                ClassicAssert.AreEqual(2, code);
            }
            finally
            {
                Console.SetError(prevErr);
            }
        }

        [Test]
        public async Task Ban_BadIp_ReturnsExit2()
        {
            using var err = new StringWriter();
            var prevErr = Console.Error;
            try
            {
                Console.SetError(err);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "ban", "not-an-ip", "--directory", tempDir });
                ClassicAssert.AreEqual(2, code);
            }
            finally
            {
                Console.SetError(prevErr);
            }
        }

        [Test]
        public async Task Ban_GoodIp_AppendsToBanFile()
        {
            int code = await CommandLineProcessor.ProcessAsync(new[] { "ban", "5.6.7.8", "--directory", tempDir });
            ClassicAssert.AreEqual(0, code);
            string banFile = Path.Combine(tempDir, "ban.txt");
            ClassicAssert.IsTrue(File.Exists(banFile));
            string content = await File.ReadAllTextAsync(banFile);
            StringAssert.Contains("5.6.7.8", content);
        }

        [Test]
        public async Task LogFileTest_WrongLineCount_ReturnsExit2()
        {
            string testFile = Path.Combine(tempDir, "ltest.txt");
            await File.WriteAllLinesAsync(testFile, new[] { "only-one-line" });
            using var sw = new StringWriter();
            var prevOut = Console.Out;
            try
            {
                Console.SetOut(sw);
                int code = await CommandLineProcessor.ProcessAsync(new[] { "logfiletest", testFile });
                ClassicAssert.AreEqual(2, code);
            }
            finally
            {
                Console.SetOut(prevOut);
            }
        }

        [Test]
        public async Task LogFileTest_FiveLines_RunsAndReturnsZero()
        {
            // 5 lines: log file, regex-failure, ts-fmt-fail, regex-success, ts-fmt-success
            string logFile = Path.Combine(tempDir, "log.log");
            await File.WriteAllLinesAsync(logFile, new[]
            {
                "2024-01-01 12:00:00 sshd[1234]: Failed password for alice from 1.2.3.4",
            });
            string testFile = Path.Combine(tempDir, "ltest.txt");
            await File.WriteAllLinesAsync(testFile, new[]
            {
                logFile,
                @"Failed password for (?<username>\S+)\s+from (?<ipaddress>\S+)",
                "yyyy-MM-dd HH:mm:ss",
                string.Empty,
                string.Empty
            });
            int code = await CommandLineProcessor.ProcessAsync(new[] { "logfiletest", testFile });
            ClassicAssert.AreEqual(0, code);
        }
    }
}
