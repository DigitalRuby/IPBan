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
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanLogFileIntegrationTests : IIPBanDelegate
    {
        private IPBanService service;
        private readonly List<IPAddressLogEvent> loggedEvents = new List<IPAddressLogEvent>();

        [SetUp]
        public void Setup()
        {
            
        }

        [TearDown]
        public void Teardown()
        {
            loggedEvents.Clear();
            IPBanService.DisposeIPBanTestService(service);
            service = null;
        }

        public void Dispose() { }

        Task IIPBanDelegate.LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp)
        {
            loggedEvents.Add(new IPAddressLogEvent(ip, userName, source, 1, IPAddressEventType.SuccessfulLogin, timestamp));
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

            await RunTest("//LogFile[Source='MSExchange']", "Exchange/*.log");
            Assert.AreEqual(1, loggedEvents.Count);
            Assert.AreEqual("180.20.20.20", loggedEvents[0].IPAddress);
            Assert.AreEqual("MSExchange", loggedEvents[0].Source);
            Assert.AreEqual(IPAddressEventType.SuccessfulLogin, loggedEvents[0].Type);
            Assert.AreEqual("user@example.com", loggedEvents[0].UserName);

            var ips = service.DB.EnumerateIPAddresses().OrderBy(i => i.IPAddress).ToArray();

            Assert.AreEqual(2, ips.Length);

            Assert.AreEqual("180.60.60.60", ips[0].IPAddress);
            Assert.AreEqual("MSExchange", ips[0].Source);
            Assert.AreEqual("user@example.com", ips[0].UserName);
            Assert.AreEqual(IPBanDB.IPAddressState.FailedLogin, ips[0].State);

            Assert.AreEqual("90.30.30.30", ips[1].IPAddress);
            Assert.AreEqual("MSExchange", ips[1].Source);
            Assert.AreEqual("user@example.com", ips[0].UserName);
            Assert.AreEqual(IPBanDB.IPAddressState.FailedLogin, ips[1].State);
        }

        private async Task RunTest(string pathAndMaskXPath, string pathAndMaskOverride)
        {
            // create a test service with log file path/mask overriden
            pathAndMaskOverride = Path.Combine(AppContext.BaseDirectory, "TestData", "LogFiles", pathAndMaskOverride);
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>(configFileModifier: config =>
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(config);
                XmlNode exchange = doc.SelectSingleNode(pathAndMaskXPath);
                XmlNode pathAndMask = exchange["PathAndMask"];
                pathAndMask.InnerText = pathAndMaskOverride;
                return doc.OuterXml;
            });
            service.IPBanDelegate = this;

            // read all the files, save contents in memory temporarily
            Dictionary<string, string> files = new Dictionary<string, string>();
            foreach (string fileName in Directory.GetFiles(Path.GetDirectoryName(pathAndMaskOverride), Path.GetFileName(pathAndMaskOverride)))
            {
                files[fileName] = File.ReadAllText(fileName);
                File.WriteAllText(fileName, string.Empty);
            }

            // force service to read all files as empty, the service always starts at the end of the file
            await service.RunCycle();

            // now write the full file contents, service will pick-up all the new text and parse it
            foreach (var file in files)
            {
                File.WriteAllText(file.Key, file.Value);
            }
            files = null;

            // run cycle again to kick off the parse of all the new text
            await service.RunCycle();
        }
    }
}
