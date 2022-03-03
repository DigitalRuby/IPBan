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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanConfigTests : IDnsLookup
    {
        private static void AssertLogFileToParse(IPBanLogFileToParse file, string failedLoginRegex, string failedLoginRegexTimestampFormat,
            int maxFileSize, string pathAndMask, int pingInterval, string platformRegex,
            string source, string successfulLoginRegex, string successfulLoginRegexTimestampFormat,
            LogLevel failedLogLevel = LogLevel.Warning, LogLevel successLogLevel = LogLevel.Warning)
        {
            Assert.AreEqual(IPBanConfig.ParseRegex(failedLoginRegex)?.ToString(), IPBanConfig.ParseRegex(file.FailedLoginRegex)?.ToString());
            Assert.AreEqual(failedLoginRegexTimestampFormat, file.FailedLoginRegexTimestampFormat);
            Assert.AreEqual(maxFileSize, file.MaxFileSize);
            Assert.AreEqual(Regex.Replace(pathAndMask.Trim().Replace('\n', '|'), "\\s+", string.Empty), Regex.Replace(file.PathAndMask.Trim().Replace('\n', '|'), "\\s+", string.Empty));
            Assert.AreEqual(pingInterval, file.PingInterval);
            Assert.AreEqual(IPBanConfig.ParseRegex(platformRegex)?.ToString(), IPBanConfig.ParseRegex(file.PlatformRegex)?.ToString());
            Assert.AreEqual(source, file.Source);
            Assert.AreEqual(IPBanConfig.ParseRegex(successfulLoginRegex)?.ToString(), IPBanConfig.ParseRegex(file.SuccessfulLoginRegex)?.ToString());
            Assert.AreEqual(successfulLoginRegexTimestampFormat, file.SuccessfulLoginRegexTimestampFormat);
            Assert.AreEqual(failedLogLevel, file.FailedLoginLogLevel);
            Assert.AreEqual(successLogLevel, file.SuccessfulLoginLogLevel);
        }

        private static void AssertLogFilesToParse(IPBanConfig cfg)
        {
            const int maxFileSize = 16777216;
            const int pingInterval = 10000;

            // path and mask, fail expression, fail timestamp format, success expression, success timestamp format, platform regex, source
            object[] logFileData = new object[]
            {
                "/var/log/auth*.log\n/var/log/secure*\n/var/log/messages",
                @"failed\s+password\s+for\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh|did\s+not\s+receive\s+identification\s+string\s+from\s+(?<ipaddress>[^\s]+)|connection\s+closed\s+by\s+((invalid\s+user\s+)?(?<username>[^\s]+)\s+)?(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+authenticating\s+user\s+(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]",
                @"",
                @"Accepted\s+password\s+for\s+(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh",
                @"",
                "Linux", "SSH",

                "/var/log/ipbancustom*.log",
                @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>[^,\n]+),\ssource:\s(?<source>[^,\n]+)?,\suser:\s(?<username>[^\s,]+)?",
                @"",
                @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>[^,\n]+),\ssource:\s(?<source>[^,\n]+)?,\suser:\s(?<username>[^\s,]+)?",
                @"",
                "Linux", "IPBanCustom",

                "C:/Program Files/Microsoft/Exchange Server/*/TransportRoles/Logs/FrontEnd/ProtocolLog/**.log",
                @"^(?<timestamp>[0-9TZ\-:\.]+),(?:.*?\\(?:External\sAuthenticated\sRelay|Internet\sRecive\sFrontend),)?(?:[^,\n]*,){3}(?<ipaddress>[^,\n]+).*?(?:(?:504\s5\.7\.4\sUnrecognized\sauthentication\stype)|(?:LogonDenied\n?.*?(?:User\:|User\sName\:)\s(?<username>[^\n,""]+)))",
                @"",
                @"^(?<timestamp>[0-9TZ\-:\.]+)?,(?:[^,\n]*,){4}(?<ipaddress>[^,\n]+),(?:[^,\n]*),(?<username>[^,\n]*),authenticated",
                @"",
                "Windows", "MSExchange",

                "C:/Program Files/Smarter Tools/Smarter Mail/**/*.log\nC:/Program Files (x86)/Smarter Tools/Smarter Mail/**/*.log\nC:/SmarterMail/logs/**/*.log\nC:/Smarter Mail/logs/**/*.log",
                @"\[(?<ipaddress>[^\]\n]+)\](?:\[[^\]\n]*\]\s+).*?(?:(?:The\sdomain\sgiven\sin\sthe\sEHLO\scommand\sviolates\san\sEHLO\sSMTP)|(?:IP\sblocked\sby\sbrute\sforce\sabuse\sdetection\srule)|(?:login\sfailed)|(?:IP\sblocked\sby\sbrute\sforce\sabuse\sdetection\srule)|(?:IP\sis\sblacklisted)|(?:too\smany\sauthentication\sfailures)|(?:Authentication\sfailed)|(?:EHLO\sSMTP\sblocking\srule)|(?:IP\sblocked\sby\sbrute\sforce\sabuse\sdetection\srule)|(?:IP\sis\sblacklisted)|(?:Mail\srejected\sdue\sto\sSMTP\sSpam\sBlocking)|(?:Too\smany\sauthentication\sfailures))",
                @"",
                @"",
                @"",
                "Windows", "SmarterMail",

                "C:/Program Files (x86)/Mail Enable/Logging/SMTP/SMTP-Activity-*.log\nC:/Program Files/Mail Enable/Logging/SMTP/SMTP-Activity-*.log\nC:/Program Files (x86)/Mail Enable/Logging/IMAP\nC:/Program Files/Mail Enable/Logging/IMAP",
                @"^(?<timestamp>[0-9\/:\s]+)SMTP\-IN\s+[^\s]+\s+[^\s]+\s(?<ipaddress>[^\s]+)\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+Invalid\sUsername\sor\sPassword\s+[^\s]+\s+[^\s]+\s+(?<username>[^\n]+)$|^(?<timestamp>[0-9\/:\s]+)IMAP\-IN\s+[^\s]+\s+(?<ipaddress>[^\s]+)\s+LOGIN\s+LOGIN\s+""(?<username>[^""]+)""\s+""[^""]+""\s+[^\s]+\s+NO\s+LOGIN\s+Failed\s+[^\s]+\s+Invalid\s+username\s+or\s+password[^\n]*$",
                @"MM/dd/yy HH:mm:ss",
                @"",
                @"",
                "Windows", "MailEnable",

                "C:/Program Files/Tomcat/logs/**/*access_log*.txt\n/var/log/httpd/access_log",
                @"^(?<ipaddress>[^\s]+)\s.*?\[(?<timestamp>.*?)\].*?(?:(?:\s40[034]\s(-|[0-9]+))|((php|md5sum|cgi-bin|joomla).*?\s404\s[0-9]+|\s400\s-))[^\n]*",
                @"dd/MMM/yyyy:HH:mm:ss zzzz",
                @"",
                @"",
                "Windows|Linux", "Apache",

                "C:/IPBanCustomLogs/**/*.log",
                @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>[^,\n]+),\ssource:\s(?<source>[^,\n]+)?,\suser:\s(?<username>[^\s,]+)?",
                @"",
                @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>[^,\n]+),\ssource:\s(?<source>[^,\n]+)?,\suser:\s(?<username>[^\s,]+)?",
                @"",
                "Windows", "IPBanCustom"
            };

            Assert.AreEqual(logFileData.Length / 7, cfg.LogFilesToParse.Count);
            for (int i = 0; i < logFileData.Length; i += 7)
            {
                AssertLogFileToParse(cfg.LogFilesToParse[i / 7],
                    (string)logFileData[i + 1],
                    (string)logFileData[i + 2],
                    maxFileSize,
                    (string)logFileData[i],
                    pingInterval,
                    (string)logFileData[i + 5],
                    (string)logFileData[i + 6],
                    (string)logFileData[i + 3],
                    (string)logFileData[i + 4]);
            }
        }

        private static void AssertEventViewerGroup(EventViewerExpressionGroup group, string keywords, int windowsMinimumMajorVersion, int windowsMinimumMinorVersion,
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
            Assert.AreEqual(LogLevel.Warning, group.LogLevel);
        }

        private static void AssertEventViewer(IPBanConfig cfg)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return;
            }

            const int minimumWindowsMajorVersion = 6;
            List<EventViewerExpressionGroup> groups = cfg.WindowsEventViewerExpressionsToBlock.Groups;
            Assert.NotNull(groups);
            Assert.AreEqual(13, groups.Count);
            AssertEventViewerGroup(groups[0], "0x8010000000000000", minimumWindowsMajorVersion, 0, false, "Security", "RDP", "//EventID", "^(4625|5152)$", "//Data[@Name='IpAddress' or @Name='Workstation' or @Name='SourceAddress']", "(?<ipaddress>.+)", "//Data[@Name='ProcessName']", "(?<source_IIS>c:\\\\Windows\\\\System32\\\\inetsrv\\\\w3wp.exe)?$");
            AssertEventViewerGroup(groups[1], "0x8010000000000000", minimumWindowsMajorVersion, 0, false, "Security", "RDP", "//EventID", "^4653$", "//Data[@Name='FailureReason']", ".", "//Data[@Name='RemoteAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[2], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "IPBanCustom", "//Data", @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?ipban\sfailed\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+)?,\suser:\s(?<username>[^\s,]+)?");
            AssertEventViewerGroup(groups[3], "0x90000000000000", minimumWindowsMajorVersion, 0, false, "Application", "MSSQL", "//Provider[contains(@Name,'MSSQL')]", string.Empty, "//EventID", "^18456$", "(//Data)[1]", "^(?<username>.+)$", "(//Data)[2]", @"^(?!Reason\:\sFailed\sto\sopen\sthe\sexplicitly\sspecified\sdatabase).", "(//Data)[3]", @"\[CLIENT\s?:\s?(?<ipaddress>[^\]]+)\]");
            AssertEventViewerGroup(groups[4], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "MySQL", "//Provider[@Name='MySQL']", string.Empty, "//Data", "Access denied for user '?(?<username>[^']+)'@'(?<ipaddress>[^']+)'");
            AssertEventViewerGroup(groups[5], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "PostgreSQL", "//Provider[@Name='PostgreSQL']", string.Empty, "//Data", "host=(?<ipaddress>[^ ]+)");
            AssertEventViewerGroup(groups[6], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "System", "MSExchange", "//Provider[@Name='MSExchangeTransport']", string.Empty, "//Data", "LogonDenied", "//Data", "(?<ipaddress_exact>.+)");
            AssertEventViewerGroup(groups[7], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "phpMyAdmin", "//Data", "phpMyAdmin", "//Data", @"user\sdenied:\s+(?<username>[^\s]+)\s+\(mysql-denied\)\s+from\s+(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[8], "0x4000000000000000", minimumWindowsMajorVersion, 0, false, "OpenSSH/Operational", "SSH", "//Data[@Name='payload']", @"failed\s+password\s+for\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh|did\s+not\s+receive\s+identification\s+string\s+from\s+(?<ipaddress>[^\s]+)|connection\s+closed\s+by\s+((invalid\s+user\s+)?(?<username>[^\s]+)\s+)?(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(invalid\s+user\s+)?(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]|disconnected\s+from\s+authenticating\s+user\s+(?<username>[^\s]+)\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+\[preauth\]");
            AssertEventViewerGroup(groups[9], "0x4000000000000000", minimumWindowsMajorVersion, 0, false, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "RDP", "//Opcode", "^14$", "//Data[@Name='ClientIP' or @Name='IPString']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[10], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "Application", "VNC", "//EventID", "^258$", "//Data", @"Authentication\sfailed\sfrom\s(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[11], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "System", "RRAS", "//EventID", "^20271$", "(//Data)[2]", @"(?<username>.*)", "(//Data)[3]", @"(?<ipaddress>.+)", "(//Data)[4]", @"denied|(Die\sRemoteverbindung\swurde\sverweigert)");
            AssertEventViewerGroup(groups[12], "0x80000000000000", minimumWindowsMajorVersion, 0, false, "VisualSVNServer", "SVN", "//EventID", "^1004$", "(//Data)[1]", @"user\s(?<username>.*?):\s\(.*\)\s.*?(falsch|wrong|incorrect|bad)", "(//Data)[2]", @"(?<ipaddress_exact>.+)");

            groups = cfg.WindowsEventViewerExpressionsToNotify.Groups;
            Assert.NotNull(groups);
            Assert.AreEqual(5, groups.Count);
            AssertEventViewerGroup(groups[0], "0x8020000000000000", minimumWindowsMajorVersion, 0, true, "Security", "RDP", "//EventID", "^4624$", "//Data[@Name='ProcessName' or @Name='LogonProcessName']", "winlogon|svchost|ntlmssp", "//Data[@Name='IpAddress' or @Name='Workstation' or @Name='SourceAddress']", "(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[1], "0x4000000000000000", minimumWindowsMajorVersion, 0, true, "OpenSSH/Operational", "SSH", "//Data[@Name='payload']", @"Accepted\s+password\s+for\s+(?<username>[^\s]+)\s+from\s+(?<ipaddress>[^\s]+)\s+port\s+[0-9]+\s+ssh");
            AssertEventViewerGroup(groups[2], "0x80000000000000", minimumWindowsMajorVersion, 0, true, "Application", "IPBanCustom", "//Data", @"(?<timestamp>\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(?:\.\d+)?Z?)?(?:,\s)?ipban\ssuccess\slogin,\sip\saddress:\s(?<ipaddress>[^,]+),\ssource:\s(?<source>[^,]+)?,\suser:\s(?<username>[^\s,]+)?");
            AssertEventViewerGroup(groups[3], "0x80000000000000", minimumWindowsMajorVersion, 0, true, "Application", "VNC", "//EventID", "^257$", "//Data", @"Authentication\spassed\sby\s(?<ipaddress>.+)");
            AssertEventViewerGroup(groups[4], "0x8020000000000000", minimumWindowsMajorVersion, 0, true, "System", "RRAS", "//EventID", "^6272$", "//Data[@Name='SubjectUserName']", @"(?<username>[^\\\/]+)$", "//Data[@Name='CallingStationID']", "(?<ipaddress>.+)", "//Data[@Name='EAPType']", "\\s?secured\\spassword\\s?");
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
                Assert.IsEmpty(cfg.BlacklistFilter.IPAddressRanges);
                Assert.IsTrue(string.IsNullOrEmpty(cfg.BlacklistFilter.Regex?.ToString()));
                Assert.IsFalse(cfg.ClearBannedIPAddressesOnRestart);
                Assert.IsFalse(cfg.ClearFailedLoginsOnSuccessfulLogin);
                Assert.IsFalse(cfg.ProcessInternalIPAddresses);
                Assert.AreEqual(TimeSpan.FromSeconds(15.0), cfg.CycleTime);
                Assert.AreEqual(TimeSpan.FromDays(1.0), cfg.ExpireTime);
                Assert.AreEqual("https://checkip.amazonaws.com/", cfg.ExternalIPAddressUrl);
                Assert.AreEqual(5, cfg.FailedLoginAttemptsBeforeBan);
                Assert.AreEqual(20, cfg.FailedLoginAttemptsBeforeBanUserNameWhitelist);
                Assert.AreEqual("IPBan_", cfg.FirewallRulePrefix);
                Assert.AreEqual(TimeSpan.FromSeconds(1.0), cfg.MinimumTimeBetweenFailedLoginAttempts);
                Assert.IsEmpty(cfg.ProcessToRunOnBan);
                Assert.IsEmpty(cfg.ProcessToRunOnUnban);
                Assert.IsFalse(cfg.ResetFailedLoginCountForUnbannedIPAddresses);
                Assert.IsTrue(cfg.UseDefaultBannedIPAddressHandler);
                Assert.IsEmpty(cfg.UserNameWhitelist);
                Assert.IsEmpty(cfg.UserNameWhitelistRegex);
                Assert.IsEmpty(cfg.WhitelistFilter.IPAddressRanges);
                Assert.IsTrue(string.IsNullOrEmpty(cfg.WhitelistFilter.Regex?.ToString()));
                Assert.AreEqual(0, cfg.ExtraRules.Count);
                Assert.AreEqual(cfg.FirewallUriRules.Trim(), "EmergingThreats,01:00:00:00,https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt");

                AssertLogFilesToParse(cfg);
                AssertEventViewer(cfg);
                string xml = await service.ConfigReaderWriter.ReadConfigAsync();
                IPBanConfig prod = IPBanConfig.LoadFromXml(xml);
                Assert.IsTrue(prod.UseDefaultBannedIPAddressHandler);
            }
            finally
            {
                IPBanService.DisposeIPBanTestService(service);
            }
        }

        /// <summary>
        /// Test that we can parse a blacklist or whitelist with comments
        /// </summary>
        [Test]
        public void TestListComments()
        {
            IPBanConfig config = IPBanConfig.LoadFromXml("<?xml version='1.0'?><configuration>" +
                "<appSettings><add key='Whitelist' value='99.99.99.99?TestIP?2020-05-25," +
                "88.88.88.88?TestIP2?2020-05-24' /></appSettings></configuration>",
                DefaultDnsLookup.Instance);
            Assert.AreEqual(string.Join(",", config.WhitelistFilter.IPAddressRanges.OrderBy(i => i)), "88.88.88.88,99.99.99.99");
            Assert.IsTrue(config.IsWhitelisted("99.99.99.99"));
            Assert.IsTrue(config.IsWhitelisted("88.88.88.88"));
            Assert.IsFalse(config.IsWhitelisted("77.77.77.77"));
        }

        [Test]
        public void TestWhitelistDns()
        {
            IPBanConfig config = IPBanConfig.LoadFromXml("<?xml version='1.0'?><configuration>" +
                "<appSettings><add key='Whitelist' value='test.com' /></appSettings></configuration>",
                this);
            Assert.IsTrue(config.WhitelistFilter.IsFiltered("99.88.77.66"));
            Assert.IsFalse(config.BlacklistFilter.IsFiltered("99.88.77.66"));
        }

        [Test]
        public void TestBlacklistDns()
        {
            IPBanConfig config = IPBanConfig.LoadFromXml("<?xml version='1.0'?><configuration>" +
                "<appSettings><add key='Blacklist' value='test.com' /></appSettings></configuration>",
                this);
            Assert.IsFalse(config.WhitelistFilter.IsFiltered("99.88.77.66"));
            Assert.IsTrue(config.BlacklistFilter.IsFiltered("99.88.77.66"));
        }

        public Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress)
        {
            if (hostNameOrAddress == "test.com")
            {
                return Task.FromResult<IPAddress[]>(new IPAddress[] { IPAddress.Parse("99.88.77.66") });
            }
            throw new NotImplementedException();
        }

        Task<IPHostEntry> IDnsLookup.GetHostEntryAsync(string hostNameOrAddress)
        {
            throw new NotImplementedException();
        }

        Task<string> IDnsLookup.GetHostNameAsync(string hostNameOrAddress)
        {
            throw new NotImplementedException();
        }
    }
}
