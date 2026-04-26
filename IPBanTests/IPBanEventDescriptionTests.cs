using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using DigitalRuby.IPBanCore;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanEventDescriptionTests
    {
        private IPBanService service;
        private string tempLogPath;

        [SetUp]
        public void SetUp()
        {
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            service.Firewall.Truncate();
            tempLogPath = Path.Combine(AppContext.BaseDirectory, "testevents.log").Replace('\\', '/');
            File.WriteAllText(tempLogPath, string.Empty);
        }

        [TearDown]
        public void TearDown()
        {
            IPBanService.DisposeIPBanTestService(service);
            service = null;
            if (File.Exists(tempLogPath))
            {
                try { File.Delete(tempLogPath); } catch { }
            }
        }

        [Test]
        public async Task LogFile_WithDescriptionTest_IgnoredThenProcessedWhenCleared()
        {
            // 1. Add custom log file with Description=test (should ignore events)
            await ApplyLogFileConfig(descriptionValue: "test");

            // Simulate initial scan (empty file) so tail starts at end
            await service.RunCycleAsync();

            // Append a failed login line containing ip 1.2.3.4
            File.AppendAllText(tempLogPath, "failed login from 1.2.3.4 user testuser\n");

            // Run cycles to allow scanner + processing
            await service.RunCycleAsync();
            await service.RunCycleAsync();

            // Expect no banned ip (event ignored because IsTest set)
            ClassicAssert.AreEqual(0, service.Firewall.EnumerateBannedIPAddresses().Count(), "No IPs should be banned when Description=test");

            // 2. Re-write config clearing Description so processing occurs
            await ApplyLogFileConfig(descriptionValue: "");
            await service.RunCycleAsync();

            // Append a second line with different ip 5.6.7.8
            File.AppendAllText(tempLogPath, "failed login from 5.6.7.8 user testuser\n");

            // Two cycles: parse + process + firewall apply
            await service.RunCycleAsync();
            await service.RunCycleAsync();

            var banned = service.Firewall.EnumerateBannedIPAddresses().ToArray();
            ClassicAssert.Contains("5.6.7.8", banned, "Second IP should be processed and banned after clearing Description");
            ClassicAssert.IsFalse(banned.Contains("1.2.3.4"), "First IP should not have been processed");
        }

        [Test]
        public async Task EventViewer_GroupDescriptionTest_IgnoredThenProcessedWhenCleared()
        {
            if (!OSUtility.IsWindows)
            {
                Assert.Ignore("Windows only test");
            }

            // Modify first RDP failed login group to add <Description>test</Description> and set threshold to 1
            await ApplyEventViewerGroupDescription("test");
            await service.RunCycleAsync();

            string testIp = "9.9.9.9";
            string xml = $@"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2024-01-01T00:00:00.0000000Z'/><Channel>Security</Channel><Computer>test</Computer></System><EventData><Data Name='IpAddress'>{testIp}</Data><Data Name='TargetUserName'>user1</Data></EventData></Event>";

            service.EventViewer.ProcessEventViewerXml(xml);
            await service.RunCycleAsync(); // process pending log events (ignored)
            await service.RunCycleAsync(); // ensure firewall update cycle passes

            ClassicAssert.AreEqual(0, service.Firewall.EnumerateBannedIPAddresses().Count(), "Event viewer event should be ignored when Description=test");

            // Clear description and resend event - should now process and ban (threshold 1)
            await ApplyEventViewerGroupDescription("");
            await service.RunCycleAsync();
            service.EventViewer.ProcessEventViewerXml(xml);
            await service.RunCycleAsync();
            await service.RunCycleAsync();

            var banned = service.Firewall.EnumerateBannedIPAddresses().ToArray();
            ClassicAssert.Contains(testIp, banned, "IP should be banned once Description cleared");
        }

        private async Task ApplyLogFileConfig(string descriptionValue)
        {
            string xml = service.Config.Xml;
            XmlDocument doc = new();
            doc.LoadXml(xml);
            // Remove any previous test log file entries we added
            var existing = doc.SelectNodes("//LogFile[Source='TestSource']");
            if (existing != null)
            {
                foreach (XmlNode node in existing)
                {
                    node.ParentNode.RemoveChild(node);
                }
            }
            var logFilesNode = doc.SelectSingleNode("//LogFiles");
            var logFile = doc.CreateElement("LogFile");
            void Add(string name, string val)
            {
                var e = doc.CreateElement(name);
                e.InnerText = val;
                logFile.AppendChild(e);
            }
            Add("Source", "TestSource");
            Add("PathAndMask", tempLogPath);
            Add("FailedLoginRegex", @"(?<ipaddress>1\.2\.3\.4)|(?<ipaddress>5\.6\.7\.8)");
            if (descriptionValue != null)
            {
                Add("Description", descriptionValue);
            }
            Add("PlatformRegex", ".");
            Add("PingInterval", "50");
            Add("MaxFileSize", "0");
            Add("FailedLoginThreshold", "1"); // immediate ban once processed
            logFilesNode.AppendChild(logFile);

            await service.ConfigReaderWriter.WriteConfigAsync(doc.OuterXml);
        }

        private async Task ApplyEventViewerGroupDescription(string descriptionValue)
        {
            string xml = service.Config.Xml;
            XmlDocument doc = new();
            doc.LoadXml(xml);
            var group = doc.SelectSingleNode("//ExpressionsToBlock//Group[Source='RDP']");
            ClassicAssert.IsNotNull(group, "RDP group not found in config");
            var desc = group["Description"];
            if (desc == null && descriptionValue != null)
            {
                desc = doc.CreateElement("Description");
                group.AppendChild(desc);
            }
            if (desc != null)
            {
                desc.InnerText = descriptionValue;
            }
            // ensure threshold is 1 so single event bans
            var threshold = group["FailedLoginThreshold"];
            if (threshold == null)
            {
                threshold = doc.CreateElement("FailedLoginThreshold");
                group.AppendChild(threshold);
            }
            threshold.InnerText = "1";
            await service.ConfigReaderWriter.WriteConfigAsync(doc.OuterXml);
        }
    }
}
