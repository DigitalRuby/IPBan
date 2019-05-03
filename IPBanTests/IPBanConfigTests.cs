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
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using DigitalRuby.IPBan;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanConfigTests
    {
        private void AssertLogFileToParse(IPBanLogFileToParse file, string failedLoginRegex, int maxFileSize, string pathAndMask, int pingInterval, string platformRegex,
            bool recursive, string source, string successfulLoginRegex)
        {
            Assert.AreEqual(IPBanConfig.ParseRegex(failedLoginRegex)?.ToString(), IPBanConfig.ParseRegex(file.FailedLoginRegex)?.ToString());
            Assert.AreEqual(maxFileSize, file.MaxFileSize);
            Assert.AreEqual(Regex.Replace(pathAndMask.Trim().Replace('\n', '|'), "\\s+", string.Empty), Regex.Replace(file.PathAndMask.Trim().Replace('\n', '|'), "\\s+", string.Empty));
            Assert.AreEqual(pingInterval, file.PingInterval);
            Assert.AreEqual(IPBanConfig.ParseRegex(platformRegex)?.ToString(), IPBanConfig.ParseRegex(file.PlatformRegex)?.ToString());
            Assert.AreEqual(recursive, file.Recursive);
            Assert.AreEqual(source, file.Source);
            Assert.AreEqual(IPBanConfig.ParseRegex(successfulLoginRegex)?.ToString(), IPBanConfig.ParseRegex(file.SuccessfulLoginRegex)?.ToString());
        }

        private void AssertLogFilesToParse(IPBanConfig cfg)
        {
            const int maxFileSize = 16777216;
            const int pingInterval = 10000;
            const string pathAndMask1 = "/var/log/auth*.log\n/var/log/secure*";
            const string pathAndMask2 = "/var/log/ipbancustom*.log";
            const string pathAndMask3 = "C:/Program Files/Microsoft/Exchange Server/*.log";
            const string pathAndMask4 = "C:/IPBanCustomLogs/*.log";
            const string failedRegex1 = @"failed\s+password\s+for\s+(invalid\s+user\s+)?(?<username>.+?\s+)from\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+ssh|did\s+not\s+receive\s+identification\s+string\s+from\s+(?<ipaddress>[^\s]+)|connection\s+closed\s+by\s+(invalid\s+user\s+)?(?<username>.+?\s+)?(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]\s*(\(no\s+attempt\s+to\s+login\s+after\s+timeout\))?|disconnected\s+from\s+(invalid\s+user\s+)?(?<username>.+?)\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+authenticating\s+user\s+(?<username>.+?)\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]";
            const string successRegex1 = @"Accepted\s+password\s+for\s+(?<username>.+?)\s+from\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+ssh";
            const string failedRegex2 = @"ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>.+?),\ssource:\s(?<source>.+?),\suser:\s(?<username>[^\s,]+)";
            const string successRegex2 = @"ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>.+?),\ssource:\s(?<source>.+?),\suser:\s(?<username>[^\s,]+)";
            const string failedRegex3 = @".*?,.*?,.*?,.*?,(?<ipaddress>.+?),(?<username>.+?),.*?AuthFailed";
            const string successRegex3 = @"";
            const string failedRegex4 = @"ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>.+?),\ssource:\s(?<source>.+?),\suser:\s(?<username>[^\s,]+)";
            const string successRegex4 = @"ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>.+?),\ssource:\s(?<source>.+?),\suser:\s(?<username>[^\s,]+)";

            Assert.AreEqual(4, cfg.LogFilesToParse.Count);
            AssertLogFileToParse(cfg.LogFilesToParse[0], failedRegex1, maxFileSize, pathAndMask1, pingInterval, "Linux", false, "SSH", successRegex1);
            AssertLogFileToParse(cfg.LogFilesToParse[1], failedRegex2, maxFileSize, pathAndMask2, pingInterval, "Linux", false, "IPBanCustom", successRegex2);
            AssertLogFileToParse(cfg.LogFilesToParse[2], failedRegex3, maxFileSize, pathAndMask3, pingInterval, "Windows", true, "MSExchange", successRegex3);
            AssertLogFileToParse(cfg.LogFilesToParse[3], failedRegex4, maxFileSize, pathAndMask4, pingInterval, "Windows", true, "IPBanCustom", successRegex4);
        }

        private void AssertEventViewerGroup(EventViewerExpressionGroup group, string keywords, int windowsMinimumMajorVersion, int windowsMinimumMinorVersion,
            bool notifyOnly, string path, string source, params string[] expressions)
        {
            Assert.NotNull(group);
            Assert.AreEqual(keywords, group.Keywords);
            Assert.AreEqual(ulong.Parse(keywords.Replace("0x", string.Empty), System.Globalization.NumberStyles.HexNumber), group.KeywordsULONG);
            Assert.AreEqual(windowsMinimumMajorVersion, group.MinimumWindowsMajorVersion);
            Assert.AreEqual(windowsMinimumMinorVersion, group.MinimumWindowsMinorVersion);
            Assert.AreEqual(notifyOnly, group.NotifyOnly);
            Assert.AreEqual(path, group.Path);
            Assert.AreEqual(source, group.Source);
            Assert.NotNull(group.Expressions);
            Assert.AreEqual(group.Expressions.Count, expressions.Length / 2);
            for (int i = 0; i < expressions.Length;)
            {
                int groupIndex = i / 2;
                Regex regex = IPBanConfig.ParseRegex(group.Expressions[groupIndex].Regex);
                Assert.AreEqual(expressions[i++], group.Expressions[groupIndex].XPath?.Trim());
                Assert.AreEqual(expressions[i++], (regex == null ? string.Empty : regex.ToString()));
            }
        }

        private void AssertEventViewer(IPBanConfig cfg)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return;
            }

            const int minimumWindowsMajorVersion = 6;
            List<EventViewerExpressionGroup> groups = cfg.WindowsEventViewerExpressionsToBlock.Groups;
            Assert.NotNull(groups);
            Assert.AreEqual(8, groups.Count);
            AssertEventViewerGroup(groups[0], "0x8010000000000000", minimumWindowsMajorVersion, 0, false, "Security", "RDP", "//EventID", "^(4625|5152)$", "//Data[@Name='IpAddress' or @Name='Workstation' or @Name='SourceAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[1], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "IPBanCustom", "//Data", @"ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>.+?),\ssource:\s(?<source>.+?),\suser:\s(?<username>[^\s,]+)");
            AssertEventViewerGroup(groups[2], "0x90000000000000", minimumWindowsMajorVersion, 0, false, "Application", "MSSQL", "//Provider[@Name='MSSQLSERVER']", string.Empty, "//Data", @"(?!(\[CLIENT\s?:|Reason\s?:))(?<username>.+)", "//Data", @"\[CLIENT\s?:\s?(?<ipaddress>.*?)\]");
            AssertEventViewerGroup(groups[3], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "MySQL", "//Provider[@Name='MySQL']", string.Empty, "//Data", "Access denied for user '?(?<username>.*?)'@'(?<ipaddress>.*?)'");
            AssertEventViewerGroup(groups[4], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "System", "MSExchange", "//Provider[@Name='MSExchangeTransport']", string.Empty, "//Data", "LogonDenied", "//Data", "(?<ipaddress_exact>.+)");
            AssertEventViewerGroup(groups[5], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "phpMyAdmin", "//Data", "phpMyAdmin", "//Data", @"user denied: (?<username>.*?)\(mysql-denied\) from *(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[6], "0x4000000000000000", minimumWindowsMajorVersion, 0, false, "OpenSSH/Operational", "SSH", "//Data[@Name='payload']", @"failed\s+password\s+for\s+(invalid\s+user\s+)?(?<username>.+?\s+)from\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+ssh|did\s+not\s+receive\s+identification\s+string\s+from\s+(?<ipaddress>[^\s]+)|connection\s+closed\s+by\s+(invalid\s+user\s+)?(?<username>.+?\s+)?(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]\s*(\(no\s+attempt\s+to\s+login\s+after\s+timeout\))?|disconnected\s+from\s+(invalid\s+user\s+)?(?<username>.+?)\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+authenticating\s+user\s+(?<username>.+?)\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+\[preauth\]");
            AssertEventViewerGroup(groups[7], "0x4000000000000000", minimumWindowsMajorVersion, 0, false, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "RDP", "//Opcode", "^14$", "//Data[@Name='ClientIP' or @Name='IPString']", "(?<ipaddress>.+)");

            groups = cfg.WindowsEventViewerExpressionsToNotify.Groups;
            Assert.NotNull(groups);
            Assert.AreEqual(3, groups.Count);
            AssertEventViewerGroup(groups[0], "0x8000000000000000", minimumWindowsMajorVersion, 0, true, "Security", "RDP", "//EventID", "^4624$", "//Data[@Name='IpAddress' or @Name='Workstation' or @Name='SourceAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[1], "0x4000000000000000", minimumWindowsMajorVersion, 0, true, "OpenSSH/Operational", "SSH", "//Data[@Name='payload']", @"Accepted\s+password\s+for\s+(?<username>.+?)\s+from\s+(?<ipaddress>.+?)\s+port\s+[0-9]+\s+ssh");
            AssertEventViewerGroup(groups[2], "0x80000000000000", minimumWindowsMajorVersion, 0, true, "Application", "IPBanCustom", "//Data", @"ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>.+?),\ssource:\s(?<source>.+?),\suser:\s(?<username>[^\s,]+)");
        }

        [Test]
        public void TestDefaultConfig()
        {
            // ensure config file is read properly
            IPBanService service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            try
            {
                IPBanConfig cfg = service.Config;
                Assert.IsNotNull(cfg);
                Assert.AreEqual(TimeSpan.FromDays(1.0), cfg.BanTime);
                Assert.IsEmpty(cfg.BlackList);
                Assert.IsEmpty(cfg.BlackListRegex);
                Assert.IsFalse(cfg.ClearBannedIPAddressesOnRestart);
                Assert.IsFalse(cfg.CreateWhitelistFirewallRule);
                Assert.AreEqual(TimeSpan.FromSeconds(15.0), cfg.CycleTime);
                Assert.AreEqual(TimeSpan.FromDays(1.0), cfg.ExpireTime);
                Assert.AreEqual("https://checkip.amazonaws.com/", cfg.ExternalIPAddressUrl);
                Assert.AreEqual(5, cfg.FailedLoginAttemptsBeforeBan);
                Assert.AreEqual(20, cfg.FailedLoginAttemptsBeforeBanUserNameWhitelist);
                Assert.AreEqual(1, cfg.FirewallOSAndType.Count);
                Assert.AreEqual("*:Default", cfg.FirewallOSAndType.Keys.First() + ":" + cfg.FirewallOSAndType.Values.First());
                Assert.AreEqual("IPBan_", cfg.FirewallRulePrefix);
                Assert.AreEqual(TimeSpan.FromSeconds(1.0), cfg.MinimumTimeBetweenFailedLoginAttempts);
                Assert.IsEmpty(cfg.ProcessToRunOnBan);
                Assert.IsEmpty(cfg.UserNameWhitelist);
                Assert.IsEmpty(cfg.WhiteList);
                Assert.IsEmpty(cfg.WhiteListRegex);

                AssertLogFilesToParse(cfg);
                AssertEventViewer(cfg);
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }
    }
}
