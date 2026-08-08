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

using System.Linq;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// Tests for the optional Id on log file entries and event viewer groups. The id identifies which
    /// config entry triggered a login event and is omitted from logs entirely when not set.
    /// </summary>
    [TestFixture]
    public class IPBanConfigIdTests
    {
        private static IPBanConfig LoadDefaultConfig()
        {
            string path = System.IO.Path.Combine(System.AppContext.BaseDirectory, IPBanConfig.DefaultFileName);
            return IPBanConfig.LoadFromXml(System.IO.File.ReadAllText(path));
        }

        [Test]
        public void TestLogFileIdParsedFromXml()
        {
            var cfg = LoadDefaultConfig();
            var logFile = cfg.LogFilesToParse.FirstOrDefault(f => f.Source == "SSH");
            ClassicAssert.IsNotNull(logFile, "Expected the built in SSH log file entry");
            ClassicAssert.AreEqual("SSH_Linux", logFile.Id);
        }

        [Test]
        public void TestEventViewerGroupIdParsedFromXml()
        {
            var cfg = LoadDefaultConfig();

            var blockGroup = cfg.WindowsEventViewerExpressionsToBlock.Groups.FirstOrDefault(g => g.Id == "RDP_AuditFailure");
            ClassicAssert.IsNotNull(blockGroup, "Expected the built in RDP failed login group");
            ClassicAssert.AreEqual("RDP", blockGroup.Source);

            var notifyGroup = cfg.WindowsEventViewerExpressionsToNotify.Groups.FirstOrDefault(g => g.Id == "RDP_Success");
            ClassicAssert.IsNotNull(notifyGroup, "Expected the built in RDP successful login group");
            ClassicAssert.AreEqual("RDP", notifyGroup.Source);
        }

        [Test]
        public void TestAllBuiltInEntriesHaveUniqueIds()
        {
            var cfg = LoadDefaultConfig();
            var ids = cfg.LogFilesToParse.Select(f => f.Id)
                .Concat(cfg.WindowsEventViewerExpressionsToBlock.Groups.Select(g => g.Id))
                .Concat(cfg.WindowsEventViewerExpressionsToNotify.Groups.Select(g => g.Id))
                .Where(i => !string.IsNullOrWhiteSpace(i))
                .ToArray();

            ClassicAssert.IsNotEmpty(ids);
            var duplicates = ids.GroupBy(i => i).Where(g => g.Count() > 1).Select(g => g.Key).ToArray();
            ClassicAssert.IsEmpty(duplicates, "Duplicate ids in the default config: " + string.Join(", ", duplicates));
        }

        [Test]
        public void TestLogFileIdRoundTripsThroughXml()
        {
            // the web admin writes each entry back out with ToStringXml, the id must survive that
            IPBanLogFileToParse logFile = new() { Id = "MyRecipe", Source = "MySource", PathAndMask = "/var/log/test.log" };
            string xml = logFile.ToStringXml();
            StringAssert.Contains("<Id>MyRecipe</Id>", xml);
        }

        [Test]
        public void TestNullLogFileIdIsOmittedFromXml()
        {
            IPBanLogFileToParse logFile = new() { Source = "MySource", PathAndMask = "/var/log/test.log" };
            string xml = logFile.ToStringXml();
            StringAssert.DoesNotContain("<Id>", xml);
        }

        [Test]
        public void TestEventViewerGroupIdRoundTripsThroughXml()
        {
            EventViewerExpressionGroup group = new() { Id = "MyGroup", Source = "MySource", Keywords = "0x8010000000000000", Path = "Security" };
            string xml = group.ToStringXml();
            StringAssert.Contains("<Id>MyGroup</Id>", xml);
        }

        [Test]
        public void TestNullEventViewerGroupIdIsOmittedFromXml()
        {
            EventViewerExpressionGroup group = new() { Source = "MySource", Keywords = "0x8010000000000000", Path = "Security" };
            string xml = group.ToStringXml();
            StringAssert.DoesNotContain("<Id>", xml);
        }

        [Test]
        public void TestIdLogSuffixEmptyWhenNotSet()
        {
            IPAddressLogEvent evt = new("1.1.1.1", "user", "SSH", 1, IPAddressEventType.FailedLogin);
            ClassicAssert.IsNull(evt.Id);
            ClassicAssert.AreEqual(string.Empty, evt.IdLogSuffix);

            evt.Id = "   ";
            ClassicAssert.AreEqual(string.Empty, evt.IdLogSuffix, "Whitespace only id should log nothing");

            evt.Id = "SSH_Linux";
            ClassicAssert.AreEqual(", id: SSH_Linux", evt.IdLogSuffix);
            StringAssert.Contains(", id: SSH_Linux", evt.ToString());
        }
    }
}
