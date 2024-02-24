/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanLogFileParserTests : IIPAddressEventHandler
    {
        private static readonly string tempPath = LogFileScanner.NormalizeGlob(Path.Combine(OSUtility.TempFolder, "LogFileParserTest"), out _, out _);

        private readonly List<IPAddressLogEvent> failedIPAddresses = [];
        private readonly List<IPAddressLogEvent> successIPAddresses = [];

        private string fullPath;
        private string pathAndMask;

        private FileStream CreateFile()
        {
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
            }
            return new FileStream(fullPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite, 8192);
        }

        private void Cleanup()
        {
            failedIPAddresses.Clear();
            successIPAddresses.Clear();
            ExtensionMethods.DirectoryDeleteWithRetry(tempPath);
            IPBanService.UtcNow = default;
        }

        [SetUp]
        public void TestSetup()
        {
            Cleanup();
            Directory.CreateDirectory(tempPath);
            fullPath = Path.Combine(tempPath, "test1.txt");
            pathAndMask = Path.Combine(tempPath, "*.txt");
        }

        [TearDown]
        public void TestCleanup()
        {
            Cleanup();
        }

        [Test]
        public void SimpleLogParseTest()
        {
            using LogFileScanner scanner = SetupLogFileScanner(failureRegex: "__prefix__(?<ipaddress>.+)__suffix(__(?<username>.*?)__end)?",
                successRegex: "success_prefix__(?<ipaddress>.+)__suffix(__(?<username>.*?)__end)?");
            {
                using StreamWriter writer = new(CreateFile(), Encoding.UTF8) { AutoFlush = true };

                // scan once before writing any data, otherwise scanner starts at end of file and will miss
                // the first data written
                scanner.ProcessFiles();

                // start off with one ip, do not write the last newline, we will do that later
                writer.Write("asdasdasdasdasdasd ");
                writer.Write("__prefix__1.1.1.1__suffix message repeated 3 times");

                scanner.ProcessFiles();

                ClassicAssert.AreEqual(0, failedIPAddresses.Count, "Should not have found ip address yet");

                // now write a newline, this should make it pickup the line
                writer.WriteLine(" aaa ");
                writer.WriteLine();

                scanner.ProcessFiles();

                ClassicAssert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");
                ClassicAssert.AreEqual("1.1.1.1", failedIPAddresses[0].IPAddress, "First ip address is wrong");
                ClassicAssert.AreEqual("SSH", failedIPAddresses[0].Source, "First ip source is wrong");
                ClassicAssert.AreEqual(3, failedIPAddresses[0].Count, "Repeat count is wrong");
                ClassicAssert.IsNull(failedIPAddresses[0].UserName, "First user name should be null");

                scanner.ProcessFiles();

                ClassicAssert.AreEqual(1, failedIPAddresses.Count, "Should not have found more ip address yet");

                writer.WriteLine("aowefjapweojfopaejfpaoe4231    343240-302843 -204 8-23084 -0");
                writer.WriteLine("__prefix__2.2.2.2__suffix__THISUSER__end");
                writer.WriteLine("success_prefix__4.4.4.4__suffix__THISUSER__end");

                scanner.ProcessFiles();

                ClassicAssert.AreEqual(2, failedIPAddresses.Count, "Did not find all expected ip addresses");
                ClassicAssert.AreEqual("2.2.2.2", failedIPAddresses[1].IPAddress, "Second ip address is wrong");
                ClassicAssert.AreEqual("SSH", failedIPAddresses[1].Source, "First ip source is wrong");
                ClassicAssert.AreEqual("THISUSER", failedIPAddresses[1].UserName, "Second user name is wrong");
                ClassicAssert.AreEqual(1, failedIPAddresses[1].Count, "Repeat count is wrong");

                ClassicAssert.AreEqual(1, successIPAddresses.Count);
                ClassicAssert.IsTrue(successIPAddresses[0].Type == IPAddressEventType.SuccessfulLogin);
                ClassicAssert.AreEqual("4.4.4.4", successIPAddresses[0].IPAddress);
                ClassicAssert.AreEqual("SSH", successIPAddresses[0].Source);
                ClassicAssert.AreEqual("THISUSER", successIPAddresses[0].UserName);
            }

            ExtensionMethods.FileDeleteWithRetry(fullPath);
            {
                using StreamWriter writer = new(CreateFile(), Encoding.UTF8)
                {
                    AutoFlush = true
                };
                writer.WriteLine("__prefix__3.3.3.3__suffix message repeated 4 times");
                scanner.ProcessFiles();
            }
            ClassicAssert.AreEqual(3, failedIPAddresses.Count, "Did not find all expected ip addresses");
            ClassicAssert.AreEqual("3.3.3.3", failedIPAddresses[2].IPAddress, "Second ip address is wrong");
            ClassicAssert.AreEqual("SSH", failedIPAddresses[2].Source, "First ip source is wrong");
            ClassicAssert.AreEqual(4, failedIPAddresses[2].Count, "Repeat count is wrong");
        }

        [Test]
        public void TestLogFileParserMaskReplace()
        {
            IPBanService.UtcNow = new DateTime(2019, 5, 5, 1, 1, 1, DateTimeKind.Utc);
            fullPath = Path.Combine(tempPath, "log-2019-05-05.txt");
            pathAndMask = Path.Combine(tempPath, "log-{year}-{month}-{day}.txt");
            using LogFileScanner scanner = SetupLogFileScanner(failureRegex: "fail, ip: (?<ipaddress>.+), user: (?<username>.*?)",
                successRegex: "success, ip: (?<ipaddress>.+), user: (?<username>.*?)");

            File.AppendAllText(fullPath, "fail, ip: 99.99.99.99, user: testuser\n");
            File.AppendAllText(fullPath, "success, ip: 98.99.99.99, user: testuser\n");
            scanner.ProcessFiles();
            ClassicAssert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");
            ClassicAssert.AreEqual("99.99.99.99", failedIPAddresses[0].IPAddress);
            ClassicAssert.AreEqual(1, successIPAddresses.Count, "Did not find all expected ip addresses");
            ClassicAssert.AreEqual("98.99.99.99", successIPAddresses[0].IPAddress);

            // move date to non-match on log file
            IPBanService.UtcNow = new DateTime(2019, 6, 5, 1, 1, 1, DateTimeKind.Utc);
            File.AppendAllText(fullPath, "fail, ip: 97.99.99.99, user: testuser\n");
            File.AppendAllText(fullPath, "success, ip: 96.99.99.99, user: testuser\n");
            scanner.ProcessFiles();

            // should be no change in parsing as file should have dropped out
            ClassicAssert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");
            ClassicAssert.AreEqual("99.99.99.99", failedIPAddresses[0].IPAddress);
            ClassicAssert.AreEqual(1, successIPAddresses.Count, "Did not find all expected ip addresses");
            ClassicAssert.AreEqual("98.99.99.99", successIPAddresses[0].IPAddress);
        }

        [Test]
        public void TestLogFileCustomSource()
        {
            using LogFileScanner scanner = SetupLogFileScanner("(?<source_ssh1>SSH1 (?<ipaddress>.+))|(?<source_ssh2>SSH2 (?<ipaddress>.+))|(?<source_ssh4>SSH4 (?<ipaddress>.+))|(SSH Default (?<ipaddress>.+))");
            File.AppendAllText(fullPath, "SSH1 97.97.97.97\n");
            File.AppendAllText(fullPath, "SSH2 98.97.97.97\n");
            File.AppendAllText(fullPath, "SSH3 99.97.97.97\n"); // fail
            File.AppendAllText(fullPath, "SSH Default 100.97.97.97\n");
            scanner.ProcessFiles();
            ClassicAssert.AreEqual(3, failedIPAddresses.Count, "Did not find all expected ip addresses");
            ClassicAssert.AreEqual("97.97.97.97", failedIPAddresses[0].IPAddress);
            ClassicAssert.AreEqual("ssh1", failedIPAddresses[0].Source);
            ClassicAssert.AreEqual("98.97.97.97", failedIPAddresses[1].IPAddress);
            ClassicAssert.AreEqual("ssh2", failedIPAddresses[1].Source);
            ClassicAssert.AreEqual("100.97.97.97", failedIPAddresses[2].IPAddress);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[2].Source);
        }

        [Test]
        public void TestLogFileTimestamp()
        {
            using LogFileScanner scanner = SetupLogFileScanner(@"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.?\d*Z?,\s)?(?<source>.*?,)(?<ipaddress>.+)");
            File.AppendAllText(fullPath, "2020-01-11 22:34:20Z, SSH, 97.97.97.97\n");
            File.AppendAllText(fullPath, "2020-01-12 22:34:20Z, SSH, 98.97.97.97\n");
            File.AppendAllText(fullPath, "2020-01-13 22:34:20Z, SSH, 99.97.97.98\n");
            File.AppendAllText(fullPath, "2020-01-14 22:34:20.5Z, SSH, 99.97.97.98\n");
            File.AppendAllText(fullPath, "2020-01-15 22:34:21.5Z, SSH, 99.97.97.98\n");
            scanner.ProcessFiles();

            ClassicAssert.AreEqual(5, failedIPAddresses.Count, "Did not find all expected ip addresses");

            ClassicAssert.AreEqual("97.97.97.97", failedIPAddresses[0].IPAddress);
            ClassicAssert.AreEqual(1, failedIPAddresses[0].Count);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[0].Source);
            ClassicAssert.AreEqual(new DateTime(2020, 01, 11, 22, 34, 20, DateTimeKind.Utc), failedIPAddresses[0].Timestamp);

            ClassicAssert.AreEqual("98.97.97.97", failedIPAddresses[1].IPAddress);
            ClassicAssert.AreEqual(1, failedIPAddresses[1].Count);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[1].Source);
            ClassicAssert.AreEqual(new DateTime(2020, 01, 12, 22, 34, 20, DateTimeKind.Utc), failedIPAddresses[1].Timestamp);

            ClassicAssert.AreEqual("99.97.97.98", failedIPAddresses[2].IPAddress);
            ClassicAssert.AreEqual(1, failedIPAddresses[2].Count);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[2].Source);
            ClassicAssert.AreEqual(new DateTime(2020, 01, 13, 22, 34, 20, DateTimeKind.Utc), failedIPAddresses[2].Timestamp);

            ClassicAssert.AreEqual("99.97.97.98", failedIPAddresses[3].IPAddress);
            ClassicAssert.AreEqual(1, failedIPAddresses[3].Count);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[3].Source);
            ClassicAssert.AreEqual(new DateTime(2020, 01, 14, 22, 34, 20, 500, DateTimeKind.Utc), failedIPAddresses[3].Timestamp);

            ClassicAssert.AreEqual("99.97.97.98", failedIPAddresses[4].IPAddress);
            ClassicAssert.AreEqual(1, failedIPAddresses[4].Count);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[4].Source);
            ClassicAssert.AreEqual(new DateTime(2020, 01, 15, 22, 34, 21, 500, DateTimeKind.Utc), failedIPAddresses[4].Timestamp);
        }

        [Test]
        public void TestLogFileTimestampFormat()
        {
            using LogFileScanner scanner = SetupLogFileScanner(@"^(?<ipaddress>[^\s]+)\s.*?\[(?<timestamp>.*?)\].*?((php|md5sum|cgi-bin|joomla).*?\s404\s[0-9]+|\s400\s-)$",
                "dd/MMM/yyyy:HH:mm:ss zzzz");
            File.AppendAllText(fullPath, "97.97.97.97 - - [28/Mar/2020:09:30:56 -0400] \"GET /TP/html /public/index.php HTTP/1.1\" 404 1110\n");
            scanner.ProcessFiles();

            ClassicAssert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");

            ClassicAssert.AreEqual("97.97.97.97", failedIPAddresses[0].IPAddress);
            ClassicAssert.AreEqual(1, failedIPAddresses[0].Count);
            ClassicAssert.AreEqual("SSH", failedIPAddresses[0].Source);
            ClassicAssert.AreEqual(new DateTime(2020, 03, 28, 13, 30, 56, DateTimeKind.Utc), failedIPAddresses[0].Timestamp);
        }

        [Test]
        public void TestNormalizeGlob()
        {
            string[] files =
            [
                "c:/temp/file.txt",
                "c:/temp/files/*/subdir/files*.txt",
                "c:\\temp\\file.txt",
                "c:\\temp\\files\\*\\subdir\\files*.txt",
                "/var/log/all*files.txt"
            ];
            string[] outFiles =
            [
                "c:/temp/", "file.txt",
                "c:/temp/files/", "*/subdir/files*.txt",
                "c:/temp/", "file.txt",
                "c:/temp/files/", "*/subdir/files*.txt",
                "/var/log/", "all*files.txt"
            ];
            for (int i = 0; i < files.Length; i++)
            {
                string result = LogFileScanner.NormalizeGlob(files[i], out string dirPortion, out string globPortion);
                ClassicAssert.AreEqual(outFiles[i * 2], dirPortion);
                ClassicAssert.AreEqual(outFiles[(i * 2) + 1], globPortion);
                ClassicAssert.AreEqual(outFiles[i * 2] + outFiles[(i * 2) + 1], result);
            }

            ClassicAssert.Throws<ArgumentException>(() => LogFileScanner.NormalizeGlob("a.txt", out _, out _));
            ClassicAssert.Throws<ArgumentException>(() => LogFileScanner.NormalizeGlob("c:/", out _, out _));
            ClassicAssert.Throws<ArgumentException>(() => LogFileScanner.NormalizeGlob("/", out _, out _));
            ClassicAssert.Throws<ArgumentException>(() => LogFileScanner.NormalizeGlob("c:\\", out _, out _));
            ClassicAssert.Throws<ArgumentException>(() => LogFileScanner.NormalizeGlob("\\", out _, out _));
        }

        private LogFileScanner SetupLogFileScanner(string failureRegex = "",
            string failureRegexTimestampFormat = null,
            string successRegex = null,
            string successRegexTimestampFormat = null,
            string source = "SSH")
        {
            IPBanIPAddressLogFileScannerOptions options = new()
            {
                Dns = TestDnsLookup.Instance,
                EventHandler = this,
                Source = source,
                PathAndMask = pathAndMask,
                RegexFailure = failureRegex,
                RegexFailureTimestampFormat = failureRegexTimestampFormat,
                RegexSuccess = successRegex,
                RegexSuccessTimestampFormat = successRegexTimestampFormat
            };
            LogFileScanner scanner = new IPBanLogFileScanner(options);
            ExtensionMethods.FileWriteAllTextWithRetry(fullPath, string.Empty);
            scanner.ProcessFiles();
            return scanner;
        }

        void IIPAddressEventHandler.AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events)
        {
            foreach (IPAddressLogEvent evt in events)
            {
                if (evt.Type == IPAddressEventType.SuccessfulLogin)
                {
                    successIPAddresses.Add(evt);
                }
                else if (evt.Type == IPAddressEventType.FailedLogin)
                {
                    failedIPAddresses.Add(evt);
                }
                else
                {
                    throw new InvalidOperationException("Unexpected ip address event " + evt);
                }
            }
        }
    }
}
