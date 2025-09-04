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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanBanTests
    {
        private const string ip1 = "99.99.99.97";
        private const string ip2 = "99.99.99.98";
        private const string ip3 = "2a0f:5840::";
        private static readonly IPAddressLogEvent info1 = new(ip1, "test_user", "RDP", 98, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info2 = new(ip2, "test_user2", "SSH", 99, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info3 = new(ip1, "test_user", "RDP", 1, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info4 = new(ip3, "test_user", "RDP", 25, IPAddressEventType.FailedLogin);

        private IPBanService service;

        [SetUp]
        public void Setup()
        {
            // ensure a clean start
            IPBanService.UtcNow = DateTime.UtcNow;
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            ClassicAssert.AreNotEqual(typeof(IPBanMemoryFirewall), service.Firewall.GetType());
        }

        [TearDown]
        public void Teardown()
        {
            IPBanService.DisposeIPBanTestService(service);
        }

        private void AddFailedLogins(int count = -1, bool ipv6 = false)
        {
            int count1 = (count < 0 ? info1.Count : count);
            int count2 = (count < 0 ? info2.Count : count);
            service.AddIPAddressLogEvents(
            [
                new(info1.IPAddress, info1.UserName, info1.Source, count1, info1.Type),
                new(info2.IPAddress, info2.UserName, info2.Source, count2, info2.Type)
            ]);
            if (ipv6)
            {
                service.AddIPAddressLogEvents(
                [
                    new(info4.IPAddress, info4.UserName, info4.Source, count < 0 ? info4.Count : count, info4.Type),
                ]);
            }
            service.RunCycleAsync().Sync();
        }

        private void AssertIPAddressesAreBanned(int failCount1 = -1, int failCount2 = -1, int failCount3 = -1, bool ipv6 = false)
        {
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ip1, out _));
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ip2, out _));
            if (ipv6)
            {
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ip3, out _));
            }
            ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
            ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
            failCount1 = (failCount1 < 0 ? info1.Count : failCount1);
            failCount2 = (failCount2 < 0 ? info2.Count : failCount2);
            ClassicAssert.AreEqual(failCount1, e1.FailedLoginCount);
            ClassicAssert.AreEqual(failCount2, e2.FailedLoginCount);
            ClassicAssert.AreEqual(IPBanDB.IPAddressState.Active, e1.State);
            ClassicAssert.AreEqual(IPBanDB.IPAddressState.Active, e2.State);
            if (ipv6)
            {
                failCount3 = (failCount3 < 0 ? info4.Count : failCount3);
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip3, out IPBanDB.IPAddressEntry e3));
                ClassicAssert.AreEqual(failCount3, e3.FailedLoginCount);
                ClassicAssert.AreEqual(IPBanDB.IPAddressState.Active, e3.State);
            }
        }

        private void AssertIPAddressesAreNotBanned(bool exists1 = false, bool exists2 = false, bool exists3 = false,
            bool ban1 = false, bool ban2 = false, bool ban3 = false)
        {
            if (ban1)
            {
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ip1, out _));
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                ClassicAssert.AreEqual(IPBanDB.IPAddressState.Active, e1.State);
            }
            else
            {
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ip1, out _));
                if (exists1)
                {
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                    ClassicAssert.AreNotEqual(IPBanDB.IPAddressState.Active, e1.State);
                }
                else
                {
                    ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip1, out _));
                }
            }
            if (ban2)
            {
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out _));
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
                ClassicAssert.AreEqual(IPBanDB.IPAddressState.Active, e2.State);
            }
            else
            {
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ip2, out _));
                if (exists2)
                {
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
                    ClassicAssert.AreNotEqual(IPBanDB.IPAddressState.Active, e2.State);
                }
                else
                {
                    ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip2, out _));
                }
            }
            if (ban3)
            {
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip3, out _));
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip3, out IPBanDB.IPAddressEntry e3));
                ClassicAssert.AreEqual(IPBanDB.IPAddressState.Active, e3.State);
            }
            else
            {
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ip3, out _));
                if (exists3)
                {
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip3, out IPBanDB.IPAddressEntry e3));
                    ClassicAssert.AreNotEqual(IPBanDB.IPAddressState.Active, e3.State);
                }
                else
                {
                    ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip3, out _));
                }
            }
        }

        private void AssertNoIPInDB(bool one = true, bool two = true, bool three = true)
        {
            if (one)
            {
                ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip1, out _));
            }
            if (two)
            {
                ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip2, out _));
            }
            if (three)
            {
                ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip3, out _));
            }
        }

        [Test]
        public void TestBanIPAddresses()
        {
            AddFailedLogins();
            AssertIPAddressesAreBanned();

            // forget all the bans
            IPBanService.UtcNow += TimeSpan.FromDays(14.0);
            service.RunCycleAsync().Sync();

            AssertIPAddressesAreNotBanned();

            // add a single failed login, should not cause a block
            service.AddIPAddressLogEvents([info3]);
            service.RunCycleAsync().Sync();
            AssertIPAddressesAreNotBanned(true, false);
        }

        [Test]
        public void TestSuccessEventViewer()
        {
            if (OSUtility.IsWindows)
            {
                const string xml = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}' /><EventID>4624</EventID><Version>1</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2019-06-13T14:35:04.718125000Z' /><EventRecordID>14296</EventRecordID><Correlation /><Execution ProcessID='480' ThreadID='7692' /><Channel>Security</Channel><Computer>ns524406</Computer><Security /></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>CPU4406$</Data><Data Name='SubjectDomainName'>WORKGROUP</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>S-1-5-21-549477949-4172057549-3284972235-1005</Data><Data Name='TargetUserName'>rdpuser</Data><Data Name='TargetDomainName'>CPU4406</Data><Data Name='TargetLogonId'>0x1d454067</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>User32</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>CPU4406</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0xc38</Data><Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data><Data Name='IpAddress'>44.55.66.77</Data><Data Name='IpPort'>0</Data><Data Name='ImpersonationLevel'>%%1833</Data></EventData></Event>";
                service.EventViewer.ProcessEventViewerXml(xml);
                service.RunCycleAsync().Sync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("44.55.66.77"));
            }
        }

        [Test]
        public void TestFailureEventViewer()
        {
            if (OSUtility.IsWindows)
            {
                const string xml = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2020-03-04T20:58:52.555949300Z'/><EventRecordID>38600046</EventRecordID><Correlation ActivityID='{75ECDDC3-EDB3-0003-CBDD-EC75B3EDD501}'/><Execution ProcessID='696' ThreadID='4092'/><Channel>Security</Channel><Computer>MYCOMPUTER</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>33.32.31.30</Data><Data Name='IpPort'>51292</Data></EventData></Event>";
                service.EventViewer.ProcessEventViewerXml(xml);
                service.RunCycleAsync().Sync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("33.32.31.30"));
            }
        }

        [Test]
        public void TestBanIPAddressExternal()
        {
            var origExecutor = service.ProcessExecutor;
            try
            {
                DigitalRuby.IPBanCore.IPAddressProcessExecutor.TestIPAddressProcessExecutor test = new();
                service.ProcessExecutor = test;

                // add the external event to the service, denoted by count of 0 (before external property was introduced)
                service.AddIPAddressLogEvents(
                [
                    new("11.11.12.13", "TestDomain\\TestUser", "RDP", 0, IPAddressEventType.Blocked, new DateTime(2020, 01, 01))
                ]);
                service.RunCycleAsync().Sync();
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("11.11.12.13", out _));
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress("11.11.12.13", out IPBanDB.IPAddressEntry entry));
                ClassicAssert.IsNotNull(entry.BanStartDate);
                ClassicAssert.IsFalse(test.Ran);

                // ensure not ran for external events using the bool property
                service.AddIPAddressLogEvents(
                [
                    new("11.11.12.14", "TestDomain\\TestUser", "RDP", 1, IPAddressEventType.Blocked, new DateTime(2020, 01, 01), true)
                ]);
                ClassicAssert.IsFalse(test.Ran);
            }
            finally
            {
                service.ProcessExecutor = origExecutor;
            }
        }

        [Test]
        public void TestBlockIPAddresesBlockFile()
        {
            // put an ban.txt file in path, service should pick it up and ban the ip addresses
            File.WriteAllLines(service.BlockIPAddressesFileName, [ip1, ip2]);
            service.RunCycleAsync().Sync();
            AssertIPAddressesAreBanned(0, 0);
        }

        [Test]
        public void TestBlockIPAddressesMethodCall()
        {
            service.AddIPAddressLogEvents([ new(ip1, string.Empty, string.Empty, 1, IPAddressEventType.Blocked),
                new(ip2, string.Empty, string.Empty, 1, IPAddressEventType.Blocked) ]);

            // this should block the ip addresses
            service.RunCycleAsync().Sync();
            AssertIPAddressesAreBanned(0, 0);
        }

        [Test]
        public void TestUnblockIPAddresesUnblockFile()
        {
            AddFailedLogins(ipv6: true);
            AssertIPAddressesAreBanned(ipv6: true);

            // put an unban.txt file in path, service should pick it up
            File.WriteAllLines(service.UnblockIPAddressesFileName, [ip1, ip2]);

            // this should un ban the ip addresses
            service.RunCycleAsync().Sync();

            AssertIPAddressesAreNotBanned(ban3: true);
            AssertNoIPInDB(three: false);
        }

        [Test]
        public void TestUnblockIPAddressesMethodCall()
        {
            AddFailedLogins();
            AssertIPAddressesAreBanned();

            service.AddIPAddressLogEvents([ new(ip1, string.Empty, string.Empty, 1, IPAddressEventType.Unblocked),
                new(ip2, string.Empty, string.Empty, 1, IPAddressEventType.Unblocked) ]);

            // this should unblock the ip addresses
            service.RunCycleAsync().Sync();

            AssertIPAddressesAreNotBanned();
            AssertNoIPInDB();
        }

        [Test]
        public void TestPlugin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // prime linux log file
                IPBanPlugin.IPBanLoginFailed("SSH", "TestDomain\\User1", "78.88.88.88");
            }
            service.RunCycleAsync().Sync();

            for (int i = 0; i < 5; i++)
            {
                IPBanPlugin.IPBanLoginFailed("SSH", "TestDomain\\User1", "88.88.88.88");
                service.RunCycleAsync().Sync();

                // attempt to read failed logins, if they do not match, sleep a bit and try again
                for (int j = 0; j < 10 && (!service.DB.TryGetIPAddress("88.88.88.88", out IPBanDB.IPAddressEntry e) || e.FailedLoginCount != i + 1); j++)
                {
                    System.Threading.Thread.Sleep(100);
                    service.RunCycleAsync().Sync();
                }

                if (i == 0)
                {
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress("88.88.88.88", out IPBanDB.IPAddressEntry entry));
                    ClassicAssert.AreEqual("User1", entry.UserName);
                    ClassicAssert.AreEqual("SSH", entry.Source);
                }

                IPBanService.UtcNow += TimeSpan.FromMinutes(5.0);
            }
            service.RunCycleAsync().Sync();
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("88.88.88.88", out _));

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                string toDelete = $"/var/log/ipbancustom_{IPBanPlugin.ProcessName}.log";
                ExtensionMethods.FileDeleteWithRetry(toDelete);
            }

            // by default, Windows plugin goes to event viewer, we want to also make sure custom log files work on Windows
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // prime log file to parse
                string file = @"C:/IPBanCustomLogs/ipbancustom_test.log";
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                ExtensionMethods.FileWriteAllTextWithRetry(file, "awerfoajwerp jaeowr paojwer " + Environment.NewLine);
                service.RunCycleAsync().Sync();
                System.Threading.Thread.Sleep(100);
                service.RunCycleAsync().Sync();
                string data = "ipban failed login, ip address: 99.99.99.99, source: SSH, user: User2" + Environment.NewLine;
                for (int i = 0; i < 5; i++)
                {
                    File.AppendAllText(file, data);
                    IPBanService.UtcNow += TimeSpan.FromMinutes(5.0);
                    service.RunCycleAsync().Sync();

                    // attempt to read failed logins, if they do not match, sleep a bit and try again
                    for (int j = 0; j < 10 && (!service.DB.TryGetIPAddress("99.99.99.99", out IPBanDB.IPAddressEntry e) || e.FailedLoginCount != i + 1); j++)
                    {
                        System.Threading.Thread.Sleep(100);
                        service.RunCycleAsync().Sync();
                    }
                    service.RunCycleAsync().Sync();
                }
                try
                {
                    ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
                }
                finally
                {
                    ExtensionMethods.DirectoryDeleteWithRetry(Path.GetDirectoryName(file));
                    using System.Diagnostics.EventLog appLog = new("Application", System.Environment.MachineName);
                    appLog.Clear();
                }
            }
        }

        [Test]
        [Category("Smoke")]
        public void TestExtraFirewallRules()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "FirewallRules", @"
                    ReddisAllowIP;allow;10.0.0.1,10.0.0.2,192.168.1.168/24;6379;.
                    WebOnly;block;0.0.0.0/1,128.0.0.0/1,::/1,8000::/1;22,80,443,3389;^(?:(?!Windows).)+$");
            }, out string newConfig);

            List<string> rules = service.Firewall.GetRuleNames().ToList();
            string reddisRule = service.Firewall.RulePrefix + "EXTRA_ReddisAllowIP";
            string webRule = service.Firewall.RulePrefix + "EXTRA_WebOnly";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // on Windows, block is the default, so only the allow rules should show up
                ClassicAssert.IsTrue(rules.Exists((s) => s.StartsWith(reddisRule)));
                ClassicAssert.IsFalse(rules.Exists((s) => s.StartsWith(webRule)));
                ClassicAssert.AreEqual(1, service.Config.ExtraRules.Count);
                IPBanFirewallRule rule1 = service.Config.ExtraRules[0];
                string regexString = rule1.ToString();
                ClassicAssert.AreEqual("EXTRA_ReddisAllowIP;allow;10.0.0.1/32,10.0.0.2/32,192.168.1.0/24;6379;.", regexString);
            }
            else
            {
                // on Linux, both rules are needed
                ClassicAssert.AreEqual(2, service.Config.ExtraRules.Count);
                ClassicAssert.IsTrue(rules.Exists((s) => s.StartsWith(reddisRule)));
                ClassicAssert.IsTrue(rules.Exists((s) => s.StartsWith(webRule)));
                IPBanFirewallRule rule1 = service.Config.ExtraRules[0];
                IPBanFirewallRule rule2 = service.Config.ExtraRules[1];
                string regexString1 = rule1.ToString();
                string regexString2 = rule2.ToString();
                ClassicAssert.AreEqual("EXTRA_ReddisAllowIP;allow;10.0.0.1/32,10.0.0.2/32,192.168.1.0/24;6379;.", regexString1);
                ClassicAssert.AreEqual("EXTRA_WebOnly;block;0.0.0.0/1,128.0.0.0/1,::/1,8000::/1;22,80,443,3389;^(?:(?!Windows).)+$", regexString2);
            }
        }

        [Test]
        public async Task TestUserNameBanRegex()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "BlacklistRegex", "Naughty.*");
            }, out string newConfig);

            service.AddIPAddressLogEvents(
            [
                // a single failed login with a non-blacklisted user name should not get banned
                new("99.99.99.99", "Good User Name", "RDP", 1, IPAddressEventType.FailedLogin),

                // a single failed login with a blacklisted user name should get banned
                new("99.99.99.90", "NaughtyUserName", "RDP", 1, IPAddressEventType.FailedLogin)
            ]);
            await service.RunCycleAsync();
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestUserNameBan()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "Blacklist", "NaughtyUserName");
            }, out string newConfig);

            service.AddIPAddressLogEvents(
            [
                // a single failed login with a non-blacklisted user name should not get banned
                new("99.99.99.99", "Good User Name", "RDP", 1, IPAddressEventType.FailedLogin),

                // a single failed login with a blacklisted user name should get banned
                new("99.99.99.90", "NaughtyUserName", "RDP", 1, IPAddressEventType.FailedLogin)
            ]);
            await service.RunCycleAsync();
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestUserNameWhitelistRegexBan()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "UserNameWhitelistRegex", "ftp_[0-9]+");
            }, out string newConfig);

            service.AddIPAddressLogEvents(
            [
                // a single failed login with a non-blacklisted user name should not get banned
                new("99.99.99.99", "ftp_1", "RDP", 1, IPAddressEventType.FailedLogin),

                // a single failed login with a failed user name whitelist regex should get banned
                new("99.99.99.90", "NaughtyUserName", "RDP", 1, IPAddressEventType.FailedLogin)
            ]);
            await service.RunCycleAsync();
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestUserNameWhitelistBan()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "UserNameWhitelist", "OnlyMe");
            }, out string newConfig);

            service.AddIPAddressLogEvents(
            [
                // should ban, we have a user name whitelist
                new("99.99.99.90", "ftp_1", "RDP", 1, IPAddressEventType.FailedLogin),

                // should not ban after 19 attempts, user is whitelisted
                new("99.99.99.99", "onlyme", "RDP", 19, IPAddressEventType.FailedLogin)
            ]);
            await service.RunCycleAsync();

            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestNoInternalFailedLoginsOrBans()
        {
            service.AddIPAddressLogEvents(
            [
                new("10.11.12.13", "TestUser", "RDP", 9, IPAddressEventType.FailedLogin)
            ]);
            await service.RunCycleAsync();
            service.AddIPAddressLogEvents(
            [
                new("10.11.12.13", "TestUser", "RDP", 9, IPAddressEventType.FailedLogin)
            ]);
            await service.RunCycleAsync();

            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("10.11.12.13"));
        }

        [Test]
        public async Task TestBanOverrideFailedLoginThreshold()
        {
            service.AddIPAddressLogEvents(
            [
                new("11.11.12.13", "TestUser", "RDP", 9, IPAddressEventType.FailedLogin,
                    new DateTime(2020, 01, 01), failedLoginThreshold: 10)
            ]);

            await service.RunCycleAsync();
            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked("10.11.12.13"));

            service.AddIPAddressLogEvents(
            [
                new("11.11.12.13", "TestUser", "RDP", 1, IPAddressEventType.FailedLogin,
                    new DateTime(2020, 01, 01), failedLoginThreshold: 10)
            ]);

            await service.RunCycleAsync();
            ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked("11.11.12.13"));
        }

        private async Task TestMultipleBanTimespansAsync(bool resetFailedLogin)
        {
            var expectedBanTimes = new[] { TimeSpan.FromMinutes(1.0), TimeSpan.FromHours(1.0), TimeSpan.FromDays(1.0) };

            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                xml = IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "BanTime", "00:00:01:00,00:01:00:00,01:00:00:00");
                xml = IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "ResetFailedLoginCountForUnbannedIPAddresses", resetFailedLogin.ToString());
                return xml;
            }, out string newConfig);

            ClassicAssert.AreEqual(3, service.Config.BanTimes.Length);
            ClassicAssert.AreEqual(resetFailedLogin, service.Config.ResetFailedLoginCountForUnbannedIPAddresses);
            for (int i = 0; i < 3; i++)
            {
                ClassicAssert.AreEqual(expectedBanTimes[i], service.Config.BanTimes[i]);
            }

            for (int i = 0; i < 4; i++)
            {
                // forget all the bans, but they should still be in the database due to the multiple timespans as failed logins
                IPBanService.UtcNow += TimeSpan.FromDays(14.0);
                await service.RunCycleAsync();

                if (i < 3)
                {
                    if (i > 0)
                    {
                        // the ips should exist but not be banned
                        AssertIPAddressesAreNotBanned(true, true);
                    }

                    AddFailedLogins((i == 0 ? -1 : 1));

                    if (resetFailedLogin)
                    {
                        if (i > 0)
                        {
                            // after one failed login, should not be banned
                            AssertIPAddressesAreNotBanned(true, true);
                        }

                        // add more failed logins
                        AddFailedLogins();

                        // now they should be banned, failed login counts are reset upon ban
                        AssertIPAddressesAreBanned(0, 0);
                    }
                    else
                    {
                        // should have gotten back in with just a single failed login
                        AssertIPAddressesAreBanned(info1.Count + i, info2.Count + i);
                    }

                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));

                    // i == 3 means wrap around from 3 minutes back to 1 minute
                    TimeSpan expectedBanDuration = (i < 3 ? expectedBanTimes[i] : expectedBanTimes[0]);
                    ClassicAssert.AreEqual(expectedBanDuration, e1.BanEndDate - e1.BanStartDate);
                    ClassicAssert.AreEqual(expectedBanDuration, e2.BanEndDate - e2.BanStartDate);
                    if (resetFailedLogin)
                    {
                        ClassicAssert.AreEqual(0, e1.FailedLoginCount);
                        ClassicAssert.AreEqual(0, e2.FailedLoginCount);
                    }
                    else
                    {
                        ClassicAssert.AreNotEqual(0, e1.FailedLoginCount);
                        ClassicAssert.AreNotEqual(0, e2.FailedLoginCount);
                    }
                }
                else
                {
                    // the cycle will run and remove the expired ip first as they have finished the loop through the ban times, they should all have a single failed login count
                    AddFailedLogins(1);

                    // ips should exist but not be banned
                    AssertIPAddressesAreNotBanned(true, true);
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
                    ClassicAssert.IsNull(e1.BanStartDate);
                    ClassicAssert.IsNull(e2.BanStartDate);
                    ClassicAssert.IsNull(e1.BanEndDate);
                    ClassicAssert.IsNull(e2.BanEndDate);
                    ClassicAssert.AreEqual(1, e1.FailedLoginCount);
                    ClassicAssert.AreEqual(1, e2.FailedLoginCount);

                    // now add a bunch of fail logins, ip should ban with a time span of 1 minute
                    AddFailedLogins();
                    if (resetFailedLogin)
                    {
                        AssertIPAddressesAreBanned(0, 0);
                    }
                    else
                    {
                        AssertIPAddressesAreBanned(info1.Count + 1, info2.Count + 1);
                    }
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip1, out e1));
                    ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip2, out e2));
                    TimeSpan expectedBanDuration = expectedBanTimes[0];
                    ClassicAssert.AreEqual(expectedBanDuration, e1.BanEndDate - e1.BanStartDate);
                    ClassicAssert.AreEqual(expectedBanDuration, e2.BanEndDate - e2.BanStartDate);
                    if (resetFailedLogin)
                    {
                        ClassicAssert.AreEqual(0, e1.FailedLoginCount);
                        ClassicAssert.AreEqual(0, e2.FailedLoginCount);
                    }
                    else
                    {
                        ClassicAssert.AreEqual(info1.Count + 1, e1.FailedLoginCount);
                        ClassicAssert.AreEqual(info2.Count + 1, e2.FailedLoginCount);
                    }
                }
            }
        }

        private class ExternalBlocker(IIPBanService service) : IIPBanDelegate
        {
            private readonly IIPBanService service = service;

            public Task LoginAttemptFailed(string ipAddress, string source, string userName, string machineGuid,
                string osName, string osVersion, int count, DateTime timestamp, IPAddressNotificationFlags notificationFlags)
            {
                var events = new IPAddressLogEvent[] { new(ipAddress, userName, source, count, IPAddressEventType.Blocked, IPBanService.UtcNow, true, notificationFlags: notificationFlags) };
                service.AddIPAddressLogEvents(events);
                return Task.CompletedTask;
            }

            public void Dispose()
            {

            }
        }

        private async Task TestMultipleBanTimespansExternalBlockAsync(bool resetFailedLogin)
        {
            const string ipAddress = "99.99.99.99";
            const string userName = "TEST";
            const string source = "RDP";
            const IPAddressEventType type = IPAddressEventType.FailedLogin;
            service.IPBanDelegate = new ExternalBlocker(service);

            IPAddressLogEvent[] events = new IPAddressLogEvent[1];

            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                xml = IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "BanTime", "00:00:01:00,00:00:05:00,00:00:15:00,89:00:00:00");
                xml = IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "ResetFailedLoginCountForUnbannedIPAddresses", resetFailedLogin.ToString());
                return xml;
            }, out string newConfig);
            ClassicAssert.AreEqual(4, service.Config.BanTimes.Length);

            // send a block event, should get banned for 1 minute
            IPBanService.UtcNow = new DateTime(2020, 1, 1, 1, 1, 1, DateTimeKind.Utc);

            for (int i = 0; i < 2; i++)
            {
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // run cycle again, should get pinged by external blocker and ip should be blocked
                await service.RunCycleAsync();
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                ClassicAssert.IsTrue(service.DB.TryGetBanDates(ipAddress, out KeyValuePair<DateTime?, DateTime?> banDates));
                ClassicAssert.AreEqual(IPBanService.UtcNow, banDates.Key);
                ClassicAssert.AreEqual(IPBanService.UtcNow.AddMinutes(1.0), banDates.Value);

                // short step, should still be blocked
                IPBanService.UtcNow += TimeSpan.FromSeconds(1.0);
                await service.RunCycleAsync();
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));

                IPBanService.UtcNow += TimeSpan.FromMinutes(1.0);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // send a fail login event, should get banned for 5 minutes
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                DateTime savedBanDate = IPBanService.UtcNow;

                // add a failed and blocked login event, should not interfere with the ban cycle
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, IPAddressEventType.FailedLogin, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, IPAddressEventType.Blocked, IPBanService.UtcNow, true);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();

                // throw in some chaos
                IPBanService.UtcNow += TimeSpan.FromSeconds(7.213);

                // blocker will ban the ip
                await service.RunCycleAsync();

                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                ClassicAssert.IsTrue(service.DB.TryGetBanDates(ipAddress, out banDates));
                ClassicAssert.AreEqual(savedBanDate, banDates.Key);
                ClassicAssert.AreEqual(savedBanDate.AddMinutes(5.0), banDates.Value);

                IPBanService.UtcNow += TimeSpan.FromMinutes(20.0);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // send a failed login event, should get banned for 15 minutes
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // cycle again, blocker will ban
                await service.RunCycleAsync();
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                ClassicAssert.IsTrue(service.DB.TryGetBanDates(ipAddress, out banDates));
                ClassicAssert.AreEqual(IPBanService.UtcNow, banDates.Key);
                ClassicAssert.AreEqual(IPBanService.UtcNow.AddMinutes(15.0), banDates.Value);

                IPBanService.UtcNow += TimeSpan.FromMinutes(30.0);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // send a block event, should get banned for 89 days
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // cycle again, blocker will ban
                await service.RunCycleAsync();
                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                ClassicAssert.IsTrue(service.DB.TryGetBanDates(ipAddress, out banDates));
                ClassicAssert.AreEqual(IPBanService.UtcNow, banDates.Key);
                ClassicAssert.AreEqual(IPBanService.UtcNow.AddDays(89.0), banDates.Value);

                IPBanService.UtcNow += TimeSpan.FromDays(91.0);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));
            }
        }

        [Test]
        public Task TestMultipleBanTimespansResetFailedLoginCount()
        {
            return TestMultipleBanTimespansAsync(true);
        }

        [Test]
        public Task TestMultipleBanTimespansNoResetFailedLoginCount()
        {
            return TestMultipleBanTimespansAsync(false);
        }

        [Test]
        public Task TestMultipleBanTimespansExternalBlock()
        {
            return TestMultipleBanTimespansExternalBlockAsync(true);
        }

        [Test]
        public Task TestMultipleBanTimespansExternalBlockNoResetFailedLoginCount()
        {
            return TestMultipleBanTimespansExternalBlockAsync(false);
        }

        [Test]
        public void TestIPWhitelist()
        {
            RunConfigBanTest("Whitelist", "190.168.0.0", "99.99.99.99", "190.168.0.0", -1);
            RunConfigBanTest("Whitelist", "190.168.0.0/16", "99.99.99.99", "190.168.99.99", -1);
            RunConfigBanTest("Whitelist", "216.245.221.80/28", "99.99.99.99", "216.245.221.86", -1);
            RunConfigBanTest("Whitelist", "2409:8010:3000::", "2409:8010:3001::", "2409:8010:3000::", -1);
            RunConfigBanTest("Whitelist", "1.200.80.32/27", "1.200.80.64", "1.200.80.43", -1); // 1.200.80.32-1.200.80.63
        }

        [Test]
        public void TestIPWhitelistRegex()
        {
            RunConfigBanTest("WhitelistRegex", "^11.0.([0-1]).([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$", "193.168.99.99", "11.0.0.1", -1);
            RunConfigBanTest("WhitelistRegex", "^(11.0.0.*)|(99.99.99.[0-9])$", "193.168.99.99", "11.0.0.1", -1);
            RunConfigBanTest("WhitelistRegex", "^(11.0.0.*)|(99.99.99.[0-9])$", "193.168.99.99", "99.99.99.1", -1);
        }

        [Test]
        public void TestIPBlacklist()
        {
            RunConfigBanTest("Blacklist", "190.168.0.0", "190.168.0.0", "99.99.99.99", 1);
            RunConfigBanTest("Blacklist", "190.168.0.0/16", "190.168.99.99", "99.99.99.98", 1);
            RunConfigBanTest("Blacklist", "216.245.221.80/28", "216.245.221.86", "99.99.99.97", 1);
        }

        [Test]
        public void TestIPBlacklistRegex()
        {
            RunConfigBanTest("BlacklistRegex", "^11.0.([0-1]).([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$", "11.0.0.1", "193.168.99.100", 1);
            RunConfigBanTest("BlacklistRegex", "^(11.0.0.*)|(99.99.99.[0-9])$", "11.0.0.1", "193.168.99.99", 1);
            RunConfigBanTest("BlacklistRegex", "^(11.0.0.*)|(99.99.99.[0-9])$", "99.99.99.1", "193.168.99.98", 1);
            RunConfigBanTest("BlacklistRegex", ".", "99.99.99.2", null);
            RunConfigBanTest("BlacklistRegex", @"^(?:(?:194\.165\.16.*)|(?:5\.188\.62.*))", "5.188.62.140", null);
        }

        [Test]
        public async Task TestIPWhitelistMultipleEntries()
        {
            const string whitelistedIpToTry = "184.198.155.191";
            const string whitelist = "1.1.1.1|2024-10-31T14:55:47Z|adm1,2.2.2.2|2024-10-31T14:56:06Z|adm2,3.3.3.3|2024-10-30T00:56:34Z|Whitelisted from Web Admin,184.198.155.191|2024-10-31T15:45:46Z|Whitelisted from Web Admin,4.4.4.4|2024-10-31T13:59:14Z|d2,5.5.5.5|2024-10-31T13:59:31Z|testtenant,6.6.6.6?2024-11-04T16:02:34.663Z?Whitelisted from Web Admin,7.7.7.7?2024-11-22T21:52:16.962Z?Whitelisted from Web Admin";

            try
            {
                using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
                {
                    return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "Whitelist", whitelist);
                }, out string newConfig);

                var evt = new IPAddressLogEvent(whitelistedIpToTry, "admin", "RDP", 30, IPAddressEventType.FailedLogin, IPBanService.UtcNow);
                service.AddIPAddressLogEvents([evt]);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(whitelistedIpToTry));
            }
            finally
            {
                service.Firewall.Truncate();
                service.DB.Truncate(true);
            }
        }

        [Test]
        public async Task TestFailedAndSuccessLoginFromSameIPAddress()
        {
            await service.RunCycleAsync();

            string ip = "99.88.77.66";

            // we should not do failed login or ban for ip address that had a success login from same ip in the same cycle
            for (int i = 0; i < 10; i++)
            {
                service.AddIPAddressLogEvents(
                [
                    // fail login
                    new(ip, "user1", "RDP", 1, IPAddressEventType.FailedLogin),

                    // success login
                    new(ip, "user1", "RDP", 1, IPAddressEventType.SuccessfulLogin),
                ]);
            }

            await service.RunCycleAsync();

            ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ip, out _));
        }

        [Test]
        public async Task TestFailedLoginsClearOnSuccessfulLogin()
        {
            // turn on clear failed logins upon success login
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, nameof(IPBanConfig.ClearFailedLoginsOnSuccessfulLogin), "true");
            }, out string newConfig);

            string ip = "99.88.77.66";
            for (int i = 0; i < 2; i++)
            {
                service.AddIPAddressLogEvents(
                [
                    // fail login
                    new(ip, "user1", "RDP", 1, IPAddressEventType.FailedLogin),
                ]);
            }

            await service.RunCycleAsync();

            service.AddIPAddressLogEvents(
            [
                new(ip, "user1", "RDP", 1, IPAddressEventType.SuccessfulLogin),
            ]);

            await service.RunCycleAsync();

            ClassicAssert.IsFalse(service.DB.TryGetIPAddress(ip, out _));
        }

        [Test]
        public async Task TestFailedLoginsDoesNotClearOnSuccessfulLogin()
        {
            await service.RunCycleAsync();

            string ip = "99.88.77.66";
            for (int i = 0; i < 2; i++)
            {
                service.AddIPAddressLogEvents(
                [
                    // fail login
                    new(ip, "user1", "RDP", 1, IPAddressEventType.FailedLogin),
                ]);
            }

            await service.RunCycleAsync();

            service.AddIPAddressLogEvents(
            [
                new(ip, "user1", "RDP", 1, IPAddressEventType.SuccessfulLogin),
            ]);

            await service.RunCycleAsync();

            ClassicAssert.IsTrue(service.DB.TryGetIPAddress(ip, out _));
        }

        [Test]
        public async Task TestFailedLoginsCollapse()
        {
            IPBanService.UtcNow = DateTime.Parse("2022-05-16 08:31:23.7106");
            try
            {
                string ip = "99.88.77.66";
                //2022-05-16 08:31:23.7106|WARN|IPBan|Login failure: x.x.x.x, , RDP, 1
                //2022-05-16 08:31:23.7106|WARN|IPBan|Login failure: x.x.x.x, ADMINISTRATOR, RDP, 2
                service.AddIPAddressLogEvents(
                [
                    // fail login
                    new(ip, "", "RDP", 1, IPAddressEventType.FailedLogin),
                ]);

                // new failed login, should collapse and not be considered due to 1 second default min time between failed logins
                service.AddIPAddressLogEvents(
                [
                    // fail login
                    new(ip, "ADMINISTRATOR", "RDP", 10, IPAddressEventType.FailedLogin),
                ]);
                await service.RunCycleAsync();
                ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(ip));
            }
            finally
            {
                IPBanService.UtcNow = default;
            }
        }

        [Test]
        public void TestBase64EncodedUserName()
        {
            Regex regex = new("(?<ipaddress>.*)_(?<username_base64>.+)");
            var results = IPBanRegexParser.GetIPAddressEventsFromRegex(regex,
                "1.1.1.1_dGVzdHVzZXJuYW1l").ToArray();
            ClassicAssert.IsTrue(results.Length != 0);
            var result = results.First();
            ClassicAssert.AreEqual("1.1.1.1", result.IPAddress);
            ClassicAssert.AreEqual("testusername", result.UserName);
        }

        [Test]
        public void TestUserNameTruncation()
        {
            var trunc = IPBanRegexParser.TruncateUserNameChars;
            try
            {
                var results = IPBanRegexParser.GetIPAddressEventsFromRegex(new Regex("(?<ipaddress>.*)_(?<username>.+)"),
                "1.1.1.1_bob@mydomain.com").ToArray();
                ClassicAssert.IsTrue(results.Length != 0);
                var result = results.First();
                ClassicAssert.AreEqual("1.1.1.1", result.IPAddress);
                ClassicAssert.AreEqual("bob", result.UserName);

                // clear truncation
                IPBanRegexParser.TruncateUserNameChars = string.Empty;

                results = IPBanRegexParser.GetIPAddressEventsFromRegex(new Regex("(?<ipaddress>.*)_(?<username>.+)"),
                "1.1.1.1_bob@mydomain.com").ToArray();
                ClassicAssert.IsTrue(results.Length != 0);
                result = results.First();
                ClassicAssert.AreEqual("1.1.1.1", result.IPAddress);
                ClassicAssert.AreEqual("bob@mydomain.com", result.UserName);
            }
            finally
            {
                IPBanRegexParser.TruncateUserNameChars = trunc;
            }
        }

        private void RunConfigBanTest(string key, string value, string banIP, string noBanIP, int noBanIPCount = 999)
        {
            try
            {
                // turn on clear failed logins upon success login
                using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
                {
                    return IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, key, value);
                }, out string newConfig);

                List<IPAddressLogEvent> events =
                [
                    new IPAddressLogEvent(banIP, "user1", "RDP", 999, IPAddressEventType.FailedLogin),
                    !string.IsNullOrWhiteSpace(noBanIP) ? new IPAddressLogEvent(noBanIP, "user2", "RDP", noBanIPCount, IPAddressEventType.FailedLogin) : null
                ];
                service.AddIPAddressLogEvents(events);

                // process failed logins
                service.RunCycleAsync().Sync();

                ClassicAssert.IsTrue(service.Firewall.IsIPAddressBlocked(banIP, out _));
                ClassicAssert.IsTrue(service.DB.TryGetIPAddress(banIP, out IPBanDB.IPAddressEntry e1));
                ClassicAssert.AreEqual(e1.FailedLoginCount, 999);
                if (!string.IsNullOrWhiteSpace(noBanIP))
                {
                    ClassicAssert.IsFalse(service.Firewall.IsIPAddressBlocked(noBanIP, out _));
                    if (noBanIPCount > 0)
                    {
                        ClassicAssert.IsTrue(service.DB.TryGetIPAddress(noBanIP, out IPBanDB.IPAddressEntry e2));
                        ClassicAssert.AreEqual(e2.FailedLoginCount, noBanIPCount);
                    }
                    else
                    {
                        ClassicAssert.IsFalse(service.DB.TryGetIPAddress(noBanIP, out _));
                    }
                }
            }
            finally
            {
                service.Firewall.Truncate();
                service.DB.Truncate(true);
            }
        }
    }
}
