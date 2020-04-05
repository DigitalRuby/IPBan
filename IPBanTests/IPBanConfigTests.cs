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
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanConfigTests
    {
        private void AssertLogFileToParse(IPBanLogFileToParse file, string failedLoginRegex, string failedLoginRegexTimestampFormat,
            int maxFileSize, string pathAndMask, int pingInterval, string platformRegex,
            bool recursive, string source, string successfulLoginRegex, string successfulLoginRegexTimestampFormat)
        {
            Assert.AreEqual(IPBanConfig.ParseRegex(failedLoginRegex)?.ToString(), IPBanConfig.ParseRegex(file.FailedLoginRegex)?.ToString());
            Assert.AreEqual(failedLoginRegexTimestampFormat, file.FailedLoginRegexTimestampFormat);
            Assert.AreEqual(maxFileSize, file.MaxFileSize);
            Assert.AreEqual(Regex.Replace(pathAndMask.Trim().Replace('\n', '|'), "\\s+", string.Empty), Regex.Replace(file.PathAndMask.Trim().Replace('\n', '|'), "\\s+", string.Empty));
            Assert.AreEqual(pingInterval, file.PingInterval);
            Assert.AreEqual(IPBanConfig.ParseRegex(platformRegex)?.ToString(), IPBanConfig.ParseRegex(file.PlatformRegex)?.ToString());
            Assert.AreEqual(recursive, file.Recursive);
            Assert.AreEqual(source, file.Source);
            Assert.AreEqual(IPBanConfig.ParseRegex(successfulLoginRegex)?.ToString(), IPBanConfig.ParseRegex(file.SuccessfulLoginRegex)?.ToString());
            Assert.AreEqual(successfulLoginRegexTimestampFormat, file.SuccessfulLoginRegexTimestampFormat);
        }

        private void AssertLogFilesToParse(IPBanConfig cfg)
        {
            const int maxFileSize = 16777216;
            const int pingInterval = 10000;

            // path and mask, fail expression, fail timestamp format, success expression, success timestamp format, platform regex, recursive, source
            object[] logFileData = new object[]
            {
                "/var/log/auth*.log\n/var/log/secure*",
                @"failed\s+password\s+for\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh|did\s+not\s+receive\s+identification\s+string\s+from\s+(?<ipaddress>[^\s]+)|connection\s+closed\s+by\s+((invalid\s+user\s+)?(?<username>[^\s]+)\s+)?(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+authenticating\s+user\s+(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]",
                @"",
                @"Accepted\s+password\s+for\s+(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh",
                @"",
                "Linux", false, "SSH",

                "/var/log/ipbancustom*.log",
                @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.?\d*Z?,\s)?ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+),\suser:\s?(?<username>[^\s,]+)?",
                @"",
                @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.?\d*Z?,\s)?ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+),\suser:\s?(?<username>[^\s,]+)?",
                @"",
                "Linux", false, "IPBanCustom",

                "C:/Program Files/Microsoft/Exchange Server/*.log",
                @"(?<timestamp>[^,]+)?,[^,]*,[^,]*,[^,]*,(?<ipaddress>[^,]*),(?<username>[^,]*),[^,]*AuthFailed|(?<timestamp>[^,]+)?,[^,]*,[^,]*,[^,]*,[^,]*,(?<ipaddress>[^,]*),[^,]*,[^,]*,.*?LogonDenied\n.*?User Name: (?<username>.+)",
                @"",
                @"",
                @"",
                "Windows", true, "MSExchange",

                "C:/Program Files/Smarter Tools/Smarter Mail/*.log\nC:/ Program Files(x86) / Smarter Tools / Smarter Mail/*.log\nC:/SmarterMail/logs/*.log\nC:/Smarter Mail/logs/*.log",
                @"\[(?<ipaddress>[^\]]+)\](\[[^\]]*\]\s+)?(The domain given in the EHLO command violates an EHLO SMTP|IP blocked by brute force abuse detection rule)",
                @"",
                @"",
                @"",
                "Windows", true, "SmarterMail",

                "C:/Program Files/Tomcat/logs/*access_log*.txt",
                @"(?<ipaddress>[^\-\s]+)[\-\s]+[^\[]*\[(?<timestamp>[^\]]+)\].*?((php|md5sum|cgi-bin|joomla).*?\s404\s[0-9]+|\s400\s-)",
                @"dd/MMM/yyyy:HH:mm:ss zzzz",
                @"",
                @"",
                "Windows", true, "Apache",

                "C:/IPBanCustomLogs/*.log",
                @"ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+),\suser:\s?(?<username>[^\s,]+)?",
                @"",
                @"ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+),\suser:\s?(?<username>[^\s,]+)?",
                @"",
                "Windows", true, "IPBanCustom"
            };

            Assert.AreEqual(logFileData.Length / 8, cfg.LogFilesToParse.Count);
            for (int i = 0; i < logFileData.Length; i += 8)
            {
                AssertLogFileToParse(cfg.LogFilesToParse[i / 8],
                    (string)logFileData[i + 1],
                    (string)logFileData[i + 2],
                    maxFileSize,
                    (string)logFileData[i],
                    pingInterval,
                    (string)logFileData[i + 5],
                    (bool)logFileData[i + 6],
                    (string)logFileData[i + 7],
                    (string)logFileData[i + 3],
                    (string)logFileData[i + 4]);
            }
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
                Assert.AreEqual(expressions[i++], (regex is null ? string.Empty : regex.ToString()));
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
            Assert.AreEqual(11, groups.Count);
            AssertEventViewerGroup(groups[0], "0x8010000000000000", minimumWindowsMajorVersion, 0, false, "Security", "RDP", "//EventID", "^(4625|5152)$", "//Data[@Name='IpAddress' or @Name='Workstation' or @Name='SourceAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[1], "0x8010000000000000", minimumWindowsMajorVersion, 0, false, "Security", "RDP", "//EventID", "^4653$", "//Data[@Name='FailureReason']", ".", "//Data[@Name='RemoteAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[2], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "IPBanCustom", "//Data", @"ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+),\suser:\s?(?<username>[^\s,]+)?");
            AssertEventViewerGroup(groups[3], "0x90000000000000", minimumWindowsMajorVersion, 0, false, "Application", "MSSQL", "//Provider[contains(@Name,'MSSQL')]", string.Empty, "//EventID", "^18456$", "(//Data)[1]", "^(?<username>.+)$", "//Data", @"\[CLIENT\s?:\s?(?<ipaddress>[^\]]+)\]");
            AssertEventViewerGroup(groups[4], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "MySQL", "//Provider[@Name='MySQL']", string.Empty, "//Data", "Access denied for user '?(?<username>[^']+)'@'(?<ipaddress>[^']+)'");
            AssertEventViewerGroup(groups[5], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "PostgreSQL", "//Provider[@Name='PostgreSQL']", string.Empty, "//Data", "host=(?<ipaddress>[^ ]+)");
            AssertEventViewerGroup(groups[6], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "System", "MSExchange", "//Provider[@Name='MSExchangeTransport']", string.Empty, "//Data", "LogonDenied", "//Data", "(?<ipaddress_exact>.+)");
            AssertEventViewerGroup(groups[7], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "phpMyAdmin", "//Data", "phpMyAdmin", "//Data", @"user denied:\s+(?<username>[^\s]+)\s+\(mysql-denied\)\s+from\s+(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[8], "0x4000000000000000", minimumWindowsMajorVersion, 0, false, "OpenSSH/Operational", "SSH", "//Data[@Name='payload']", @"failed\s+password\s+for\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh|did\s+not\s+receive\s+identification\s+string\s+from\s+(?<ipaddress>[^\s]+)|connection\s+closed\s+by\s+((invalid\s+user\s+)?(?<username>[^\s]+)\s+)?(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+authenticating\s+user\s+(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]");
            AssertEventViewerGroup(groups[9], "0x4000000000000000", minimumWindowsMajorVersion, 0, false, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "RDP", "//Opcode", "^14$", "//Data[@Name='ClientIP' or @Name='IPString']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[10], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "VNC", "//EventID", "^258$", "//Data", @"Authentication\sfailed\sfrom\s(?<ipaddress>.+)");

            groups = cfg.WindowsEventViewerExpressionsToNotify.Groups;
            Assert.NotNull(groups);
            Assert.AreEqual(4, groups.Count);
            AssertEventViewerGroup(groups[0], "0x8020000000000000", minimumWindowsMajorVersion, 0, true, "Security", "RDP", "//EventID", "^4624$", "//Data[@Name='ProcessName']", "winlogon|svchost", "//Data[@Name='IpAddress' or @Name='Workstation' or @Name='SourceAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[1], "0x4000000000000000", minimumWindowsMajorVersion, 0, true, "OpenSSH/Operational", "SSH", "//Data[@Name='payload']", @"Accepted\s+password\s+for\s+(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh");
            AssertEventViewerGroup(groups[2], "0x80000000000000", minimumWindowsMajorVersion, 0, true, "Application", "IPBanCustom", "//Data", @"ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+),\suser:\s?(?<username>[^\s,]+)?");
            AssertEventViewerGroup(groups[3], "0x80000000000000", minimumWindowsMajorVersion, 0, true, "Application", "VNC", "//EventID", "^257$", "//Data", @"Authentication\spassed\sby\s(?<ipaddress>.+)");
        }

        [Test]
        public async Task TestDefaultConfig()
        {
            // ensure config file is read properly
            IPBanService service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            try
            {
                IPBanConfig cfg = service.Config;
                Assert.IsNotNull(cfg);
                Assert.AreEqual(TimeSpan.FromDays(1.0), cfg.BanTimes.First());
                Assert.AreEqual(1, cfg.BanTimes.Length);
                Assert.IsEmpty(cfg.BlackList);
                Assert.IsEmpty(cfg.BlackListRegex);
                Assert.IsFalse(cfg.ClearBannedIPAddressesOnRestart);
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
                Assert.IsFalse(cfg.ResetFailedLoginCountForUnbannedIPAddresses);
                Assert.IsTrue(cfg.UseDefaultBannedIPAddressHandler);
                Assert.IsEmpty(cfg.UserNameWhitelist);
                Assert.IsEmpty(cfg.UserNameWhitelistRegex);
                Assert.IsEmpty(cfg.WhiteList);
                Assert.IsEmpty(cfg.WhiteListRegex);
                Assert.AreEqual(0, cfg.ExtraRules.Count);
                Assert.AreEqual(cfg.FirewallUriRules.Trim(), "EmergingThreats,01:00:00:00,https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt");

                AssertLogFilesToParse(cfg);
                AssertEventViewer(cfg);
                string xml = await service.ReadConfigAsync();
                IPBanConfig prod = IPBanConfig.LoadFromXml(xml, null);
                Assert.IsTrue(prod.UseDefaultBannedIPAddressHandler);
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }
    }
}
