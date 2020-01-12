/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanLogFileParserTests : IIPAddressEventHandler
    {
        private static readonly string tempPath = Path.Combine(OSUtility.TempFolder, "LogFileParserTest");
        private static readonly string pathAndMask = Path.Combine(tempPath, "test1*.txt");
        private static readonly List<IPAddressLogEvent> failedIPAddresses = new List<IPAddressLogEvent>();
        private static readonly List<IPAddressLogEvent> successIPAddresses = new List<IPAddressLogEvent>();

        private static FileStream CreateFile(string name)
        {
            return new FileStream(Path.Combine(tempPath, name), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite, 8192);
        }

        private static void Cleanup()
        {
            failedIPAddresses.Clear();
            successIPAddresses.Clear();
            if (Directory.Exists(tempPath))
            {
                Directory.Delete(tempPath, true);
            }
        }

        [SetUp]
        public void TestSetup()
        {
            Cleanup();
            Directory.CreateDirectory(tempPath);
        }

        [TearDown]
        public void TestCleanup()
        {
            Cleanup();
        }

        [Test]
        public void SimpleLogParseTest()
        {
            string fullPath = Path.Combine(tempPath, "test1.txt");
            using (LogFileScanner scanner = new IPBanIPAddressLogFileScanner(this, TestDnsLookup.Instance,
                source: "SSH",
                pathAndMask: pathAndMask,
                recursive: false,
                regexFailure: "__prefix__(?<ipaddress>.+)__suffix(__(?<username>.*?)__end)?",
                regexSuccess: "success_prefix__(?<ipaddress>.+)__suffix(__(?<username>.*?)__end)?",
                pingIntervalMilliseconds: 0))
            {
                StreamWriter writer = new StreamWriter(CreateFile(fullPath), Encoding.UTF8)
                {
                    AutoFlush = true
                };

                // scan once before writing any data, otherwise scanner starts at aned of file and will miss
                // the first data written
                scanner.PingFiles();

                // start off with one ip, do not write the last newline, we will do that later
                writer.Write("asdasdasdasdasdasd ");
                writer.Write("__prefix__1.1.1.1__suffix message repeated 3 times");

                scanner.PingFiles();

                Assert.AreEqual(0, failedIPAddresses.Count, "Should not have found ip address yet");

                // now write a newline, this should make it pickup the line
                writer.WriteLine(" aaa ");
                writer.WriteLine();

                scanner.PingFiles();

                Assert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("1.1.1.1", failedIPAddresses[0].IPAddress, "First ip address is wrong");
                Assert.AreEqual("SSH", failedIPAddresses[0].Source, "First ip source is wrong");
                Assert.AreEqual(3, failedIPAddresses[0].Count, "Repeat count is wrong");
                Assert.IsNull(failedIPAddresses[0].UserName, "First user name should be null");

                scanner.PingFiles();

                Assert.AreEqual(1, failedIPAddresses.Count, "Should not have found more ip address yet");

                writer.WriteLine("aowefjapweojfopaejfpaoe4231    343240-302843 -204 8-23084 -0");
                writer.WriteLine("__prefix__2.2.2.2__suffix__THISUSER__end");
                writer.WriteLine("success_prefix__4.4.4.4__suffix__THISUSER__end");

                scanner.PingFiles();

                Assert.AreEqual(2, failedIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("2.2.2.2", failedIPAddresses[1].IPAddress, "Second ip address is wrong");
                Assert.AreEqual("SSH", failedIPAddresses[1].Source, "First ip source is wrong");
                Assert.AreEqual("THISUSER", failedIPAddresses[1].UserName, "Second user name is wrong");
                Assert.AreEqual(1, failedIPAddresses[1].Count, "Repeat count is wrong");

                Assert.AreEqual(1, successIPAddresses.Count);
                Assert.IsTrue(successIPAddresses[0].Type == IPAddressEventType.SuccessfulLogin);
                Assert.AreEqual("4.4.4.4", successIPAddresses[0].IPAddress);
                Assert.AreEqual("SSH", successIPAddresses[0].Source);
                Assert.AreEqual("THISUSER", successIPAddresses[0].UserName);

                writer.Close();

                ExtensionMethods.FileDeleteWithRetry(fullPath);

                writer = new StreamWriter(CreateFile(fullPath), Encoding.UTF8)
                {
                    AutoFlush = true
                };
                writer.WriteLine("__prefix__3.3.3.3__suffix message repeated 4 times");

                scanner.PingFiles();

                Assert.AreEqual(3, failedIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("3.3.3.3", failedIPAddresses[2].IPAddress, "Second ip address is wrong");
                Assert.AreEqual("SSH", failedIPAddresses[2].Source, "First ip source is wrong");
                Assert.AreEqual(4, failedIPAddresses[2].Count, "Repeat count is wrong");

                writer.Close();
            }
        }

        [Test]
        public void TestLogFileParserMaskReplace()
        {
            string pathAndMask = Path.Combine(tempPath, "log-{year}-{month}-{day}.txt");
            using (LogFileScanner scanner = new IPBanIPAddressLogFileScanner(this, TestDnsLookup.Instance,
                source: "SSH",
                pathAndMask: pathAndMask,
                recursive: false,
                regexFailure: "fail, ip: (?<ipaddress>.+), user: (?<username>.*?)",
                regexSuccess: "success, ip: (?<ipaddress>.+), user: (?<username>.*?)",
                pingIntervalMilliseconds: 0))
            {
                string filePath = Path.Combine(tempPath, "log-2019-05-05.txt");
                IPBanService.UtcNow = new DateTime(2019, 5, 5, 1, 1, 1, DateTimeKind.Utc);
                ExtensionMethods.FileWriteAllTextWithRetry(filePath, string.Empty);
                scanner.PingFiles();
                File.AppendAllText(filePath, "fail, ip: 99.99.99.99, user: testuser\n");
                File.AppendAllText(filePath, "success, ip: 98.99.99.99, user: testuser\n");
                scanner.PingFiles();
                Assert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("99.99.99.99", failedIPAddresses[0].IPAddress);
                Assert.AreEqual(1, successIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("98.99.99.99", successIPAddresses[0].IPAddress);

                // move date to non-match on log file
                IPBanService.UtcNow = new DateTime(2019, 6, 5, 1, 1, 1, DateTimeKind.Utc);
                File.AppendAllText(filePath, "fail, ip: 97.99.99.99, user: testuser\n");
                File.AppendAllText(filePath, "success, ip: 96.99.99.99, user: testuser\n");
                scanner.PingFiles();

                // should be no change in parsing as file should have dropped out
                Assert.AreEqual(1, failedIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("99.99.99.99", failedIPAddresses[0].IPAddress);
                Assert.AreEqual(1, successIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("98.99.99.99", successIPAddresses[0].IPAddress);
            }
        }

        [Test]
        public void TestLogFileCustomSource()
        {
            string fullPath = Path.Combine(tempPath, "test1.txt");
            using (LogFileScanner scanner = new IPBanIPAddressLogFileScanner(this, TestDnsLookup.Instance,
                source: "SSH",
                pathAndMask: pathAndMask,
                recursive: false,
                regexFailure: "(?<source_ssh1>SSH1 (?<ipaddress>.+))|(?<source_ssh2>SSH2 (?<ipaddress>.+))|(?<source_ssh4>SSH4 (?<ipaddress>.+))|(SSH Default (?<ipaddress>.+))",
                regexSuccess: null,
                pingIntervalMilliseconds: 0))
            {
                ExtensionMethods.FileWriteAllTextWithRetry(fullPath, string.Empty);
                scanner.PingFiles();
                File.AppendAllText(fullPath, "SSH1 97.97.97.97\n");
                File.AppendAllText(fullPath, "SSH2 98.97.97.97\n");
                File.AppendAllText(fullPath, "SSH3 99.97.97.97\n"); // fail
                File.AppendAllText(fullPath, "SSH Default 100.97.97.97\n");
                scanner.PingFiles();
                Assert.AreEqual(3, failedIPAddresses.Count, "Did not find all expected ip addresses");
                Assert.AreEqual("97.97.97.97", failedIPAddresses[0].IPAddress);
                Assert.AreEqual("ssh1", failedIPAddresses[0].Source);
                Assert.AreEqual("98.97.97.97", failedIPAddresses[1].IPAddress);
                Assert.AreEqual("ssh2", failedIPAddresses[1].Source);
                Assert.AreEqual("100.97.97.97", failedIPAddresses[2].IPAddress);
                Assert.AreEqual("SSH", failedIPAddresses[2].Source);
            }
        }

        [Test]
        public void TestLogFileTimestamp()
        {
            string fullPath = Path.Combine(tempPath, "test1.txt");
            using (LogFileScanner scanner = new IPBanIPAddressLogFileScanner(this, TestDnsLookup.Instance,
                source: "SSH",
                pathAndMask: pathAndMask,
                recursive: false,
                regexFailure: @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.?\d*Z?,\s)?(?<source>.*?,)(?<ipaddress>.+)",
                regexSuccess: null,
                pingIntervalMilliseconds: 0))
            {
                ExtensionMethods.FileWriteAllTextWithRetry(fullPath, string.Empty);
                scanner.PingFiles();
                File.AppendAllText(fullPath, "2020-01-11 22:34:20Z, SSH, 97.97.97.97\n");
                File.AppendAllText(fullPath, "2020-01-12 22:34:20Z, SSH, 98.97.97.97\n");
                File.AppendAllText(fullPath, "2020-01-13 22:34:20Z, SSH, 99.97.97.98\n");
                File.AppendAllText(fullPath, "2020-01-14 22:34:20.5Z, SSH, 99.97.97.98\n");
                File.AppendAllText(fullPath, "2020-01-15 22:34:21.5Z, SSH, 99.97.97.98\n");
                scanner.PingFiles();

                Assert.AreEqual(5, failedIPAddresses.Count, "Did not find all expected ip addresses");

                Assert.AreEqual("97.97.97.97", failedIPAddresses[0].IPAddress);
                Assert.AreEqual(1, failedIPAddresses[0].Count);
                Assert.AreEqual("SSH", failedIPAddresses[0].Source);
                Assert.AreEqual(new DateTime(2020, 01, 11, 22, 34, 20, DateTimeKind.Utc), failedIPAddresses[0].Timestamp);

                Assert.AreEqual("98.97.97.97", failedIPAddresses[1].IPAddress);
                Assert.AreEqual(1, failedIPAddresses[1].Count);
                Assert.AreEqual("SSH", failedIPAddresses[1].Source);
                Assert.AreEqual(new DateTime(2020, 01, 12, 22, 34, 20, DateTimeKind.Utc), failedIPAddresses[1].Timestamp);

                Assert.AreEqual("99.97.97.98", failedIPAddresses[2].IPAddress);
                Assert.AreEqual(1, failedIPAddresses[2].Count);
                Assert.AreEqual("SSH", failedIPAddresses[2].Source);
                Assert.AreEqual(new DateTime(2020, 01, 13, 22, 34, 20, DateTimeKind.Utc), failedIPAddresses[2].Timestamp);

                Assert.AreEqual("99.97.97.98", failedIPAddresses[3].IPAddress);
                Assert.AreEqual(1, failedIPAddresses[3].Count);
                Assert.AreEqual("SSH", failedIPAddresses[3].Source);
                Assert.AreEqual(new DateTime(2020, 01, 14, 22, 34, 20, 500, DateTimeKind.Utc), failedIPAddresses[3].Timestamp);

                Assert.AreEqual("99.97.97.98", failedIPAddresses[4].IPAddress);
                Assert.AreEqual(1, failedIPAddresses[4].Count);
                Assert.AreEqual("SSH", failedIPAddresses[4].Source);
                Assert.AreEqual(new DateTime(2020, 01, 15, 22, 34, 21, 500, DateTimeKind.Utc), failedIPAddresses[4].Timestamp);
            }
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
