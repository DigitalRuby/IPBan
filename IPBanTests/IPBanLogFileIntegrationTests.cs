/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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
using System.Linq;
using System.Threading.Tasks;
using System.Xml;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanLogFileIntegrationTests : IIPBanDelegate
    {
        private IPBanService service;
        private readonly List<IPAddressLogEvent> failedEvents = [];
        private readonly List<IPAddressLogEvent> successfulEvents = [];

        [SetUp]
        public void Setup()
        {

        }

        [TearDown]
        public void Teardown()
        {
            failedEvents.Clear();
            successfulEvents.Clear();
            IPBanService.DisposeIPBanTestService(service);
            service = null;
        }

        public void Dispose() => GC.SuppressFinalize(this);

        Task IIPBanDelegate.LoginAttemptFailed(string ip, string source, string userName, string machineGuid,
            string osName, string osVersion, int count, DateTime timestamp, IPAddressNotificationFlags notificationFlags)
        {
            failedEvents.Add(new IPAddressLogEvent(ip, userName, source, count, IPAddressEventType.FailedLogin, timestamp, notificationFlags: notificationFlags));
            return Task.CompletedTask;
        }

        Task IIPBanDelegate.LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid,
            string osName, string osVersion, int count, DateTime timestamp, IPAddressNotificationFlags notificationFlags)
        {
            successfulEvents.Add(new IPAddressLogEvent(ip, userName, source, count, IPAddressEventType.SuccessfulLogin, timestamp, notificationFlags: notificationFlags));
            return Task.CompletedTask;
        }

        [Test]
        public async Task TestLogFilesExchange()
        {
            // only run this test on Windows
            if (!OSUtility.IsWindows)
            {
                return;
            }

            await RunTest("//LogFile[Source='MSExchange']", "TestData/**/Exchange/*.log");

            ClassicAssert.AreEqual(1, successfulEvents.Count);
            ClassicAssert.AreEqual("180.20.20.20", successfulEvents[0].IPAddress);
            for (int i = 0; i < successfulEvents.Count; i++)
            {
                ClassicAssert.AreEqual("MSExchange", successfulEvents[i].Source);
                ClassicAssert.AreEqual(IPAddressEventType.SuccessfulLogin, successfulEvents[i].Type);
                ClassicAssert.AreEqual("user", successfulEvents[i].UserName);
            }

            // 37.49.225.153, UserName: p.kurowicki@gios.gov.pl, Source: MSExchange, Count: 1, Type: FailedLogin, Timestamp: 6/26/2021 3:01:36 PM}
            ClassicAssert.AreEqual(7, failedEvents.Count);
            failedEvents.Sort((x, y) => x.IPAddress.CompareTo(y.IPAddress));

            ClassicAssert.AreEqual("109.75.46.81", failedEvents[0].IPAddress);
            ClassicAssert.AreEqual("user", failedEvents[0].UserName);

            ClassicAssert.AreEqual("180.60.60.60", failedEvents[1].IPAddress);
            ClassicAssert.AreEqual("user", failedEvents[1].UserName);

            ClassicAssert.AreEqual("27.255.75.110", failedEvents[2].IPAddress);
            ClassicAssert.AreEqual(string.Empty, failedEvents[2].UserName);

            ClassicAssert.AreEqual("37.49.225.153", failedEvents[3].IPAddress);
            ClassicAssert.AreEqual("user", failedEvents[3].UserName);

            ClassicAssert.AreEqual("54.212.131.181", failedEvents[4].IPAddress);
            ClassicAssert.AreEqual("exctest", failedEvents[4].UserName);

            ClassicAssert.AreEqual("54.212.131.182", failedEvents[5].IPAddress);
            ClassicAssert.AreEqual("exctest", failedEvents[5].UserName);

            ClassicAssert.AreEqual("90.30.30.30", failedEvents[6].IPAddress);
            ClassicAssert.AreEqual("user", failedEvents[6].UserName);

            for (int i = 0; i < failedEvents.Count; i++)
            {
                ClassicAssert.AreEqual("MSExchange", failedEvents[i].Source);
                ClassicAssert.AreEqual(IPAddressEventType.FailedLogin, failedEvents[i].Type);
            }
        }

        [Test]
        public async Task TestLogFilesApache()
        {
            string path = Path.Combine(AppContext.BaseDirectory, "TestData/LogFiles/Apache/everything.log");
            await RunTest(null, path, doc =>
            {
                var logFiles = doc.SelectSingleNode("//LogFiles");
                var logFile = doc.CreateElement("LogFile");
                var source = doc.CreateElement("Source");
                source.InnerText = "Apache";
                logFile.AppendChild(source);
                var pathAndMask = doc.CreateElement("PathAndMask");
                pathAndMask.InnerText = path;
                logFile.AppendChild(pathAndMask);
                var failedLoginRegex = doc.CreateElement("FailedLoginRegex");
                failedLoginRegex.InnerText = @"\n(?<ipaddress>[^\s]+)[^\[]+\[(?<timestamp>[^\]]+)\]\s""(?:\\x|[^\n]+?\s(?:301|40[04])\s[0-9\-])[^\n]*";
                logFile.AppendChild(failedLoginRegex);
                var failedLoginRegexTimestampFormat = doc.CreateElement("FailedLoginRegexTimestampFormat");
                failedLoginRegexTimestampFormat.InnerText = "dd/MMM/yyyy:HH:mm:ss zzzz";
                logFile.AppendChild(failedLoginRegexTimestampFormat);
                var platformRegex = doc.CreateElement("PlatformRegex");
                platformRegex.InnerText = ".";
                logFile.AppendChild(platformRegex);
                var pingInterval = doc.CreateElement("PingInterval");
                pingInterval.InnerText = "10000";
                logFile.AppendChild(pingInterval);
                var maxFileSize = doc.CreateElement("MaxFileSize");
                maxFileSize.InnerText = "0";
                logFile.AppendChild(maxFileSize);
                var failedLoginThreshold = doc.CreateElement("FailedLoginThreshold");
                failedLoginThreshold.InnerText = "0";
                logFile.AppendChild(failedLoginThreshold);
                logFiles.AppendChild(logFile);

                var minTimeBetweenFailures = doc.SelectSingleNode("//add[@key='MinimumTimeBetweenFailedLoginAttempts']");
                minTimeBetweenFailures.Attributes["value"].Value = "00:00:00:00";
            });

            ClassicAssert.AreEqual(0, successfulEvents.Count);
            ClassicAssert.AreEqual(1, failedEvents.Count);
            ClassicAssert.AreEqual(6, failedEvents.First().Count);
        }

        [Test]
        public async Task TestLogFilesRDWeb()
        {
            string path = Path.Combine(AppContext.BaseDirectory, "TestData/LogFiles/RDWeb/everything.log");
            await RunTest(null, path, doc =>
            {
                var logFiles = doc.SelectSingleNode("//LogFiles");
                var logFile = doc.CreateElement("LogFile");
                var source = doc.CreateElement("Source");
                source.InnerText = "RDWeb";
                logFile.AppendChild(source);
                var pathAndMask = doc.CreateElement("PathAndMask");
                pathAndMask.InnerText = path;
                logFile.AppendChild(pathAndMask);
                var failedLoginRegex = doc.CreateElement("FailedLoginRegex");
                failedLoginRegex.InnerText = @"(?<timestamp_utc>\d\d\d\d\-\d\d\-\d\d\s\d\d\:\d\d\:\d\d)\s[^\s]+\sPOST\s\/RDWeb\/Pages\/[^\/]+\/login\.aspx\s[^\s]+\s[0-9]+\s-\s(?<ipaddress>[^\s]+).*\s200\s[^\n]+\n";
                logFile.AppendChild(failedLoginRegex);
                var platformRegex = doc.CreateElement("PlatformRegex");
                platformRegex.InnerText = ".";
                logFile.AppendChild(platformRegex);
                var pingInterval = doc.CreateElement("PingInterval");
                pingInterval.InnerText = "10000";
                logFile.AppendChild(pingInterval);
                var maxFileSize = doc.CreateElement("MaxFileSize");
                maxFileSize.InnerText = "0";
                logFile.AppendChild(maxFileSize);
                var failedLoginThreshold = doc.CreateElement("FailedLoginThreshold");
                failedLoginThreshold.InnerText = "0";
                logFile.AppendChild(failedLoginThreshold);
                var minTimeFailedLogins = doc.CreateElement("MinimumTimeBetweenFailedLoginAttempts");
                minTimeFailedLogins.InnerText = "00:00:00:00";
                logFile.AppendChild(minTimeFailedLogins);
                logFiles.AppendChild(logFile);
            });

            ClassicAssert.AreEqual(0, successfulEvents.Count);
            ClassicAssert.AreEqual(1, failedEvents.Count);
            ClassicAssert.AreEqual(5, failedEvents.First().Count);
        }

        private async Task RunTest(string pathAndMaskXPath, string pathAndMaskOverride, Action<XmlDocument> modifier = null)
        {
            // create a test service with log file path/mask overriden
            if (!string.IsNullOrWhiteSpace(pathAndMaskOverride))
            {
                pathAndMaskOverride = Path.Combine(AppContext.BaseDirectory, pathAndMaskOverride).Replace('\\', '/');
            }
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>(configFileModifier: config =>
            {
                XmlDocument doc = new();
                doc.LoadXml(config);
                if (!string.IsNullOrWhiteSpace(pathAndMaskXPath))
                {
                    var logFileNode = doc.SelectSingleNode(pathAndMaskXPath);
                    var pathAndMask = logFileNode["PathAndMask"];
                    pathAndMask.InnerText = pathAndMaskOverride;
                }
                modifier?.Invoke(doc);
                return doc.OuterXml;
            });
            service.IPBanDelegate = this;

            // read all the files, save contents in memory temporarily
            Dictionary<string, string> files = [];
            foreach (var file in LogFileScanner.GetFiles(pathAndMaskOverride))
            {
                files[file.FileName] = File.ReadAllText(file.FileName);
                File.WriteAllText(file.FileName, string.Empty);
            }

            // force service to read all files as empty, the service always starts at the end of the file
            await service.RunCycleAsync();

            // now write the full file contents, service will pick-up all the new text and parse it
            foreach (var file in files)
            {
                File.WriteAllText(file.Key, file.Value);
            }
            files = null;

            // run cycle again to kick off the parse of all the new text
            await service.RunCycleAsync();
        }
    }
}
