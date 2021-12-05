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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanBanTests
    {


        private const string ip1 = "99.99.99.97";
        private const string ip2 = "99.99.99.98";
        private static readonly IPAddressLogEvent info1 = new(ip1, "test_user", "RDP", 98, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info2 = new(ip2, "test_user2", "SSH", 99, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info3 = new(ip1, "test_user", "RDP", 1, IPAddressEventType.FailedLogin);

        private IPBanService service;

        [SetUp]
        public void Setup()
        {
            // ensure a clean start
            IPBanService.UtcNow = DateTime.UtcNow;
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
            Assert.AreNotEqual(typeof(IPBanMemoryFirewall), service.Firewall.GetType());
        }

        [TearDown]
        public void Teardown()
        {
            IPBanService.DisposeIPBanTestService(service);
        }

        private void AddFailedLogins(int count = -1)
        {
            int count1 = (count < 0 ? info1.Count : count);
            int count2 = (count < 0 ? info2.Count : count);
            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent(info1.IPAddress, info1.UserName, info1.Source, count1, info1.Type),
                new IPAddressLogEvent(info2.IPAddress, info2.UserName, info2.Source, count2, info2.Type)
            });
            service.RunCycleAsync().Sync();
        }

        private void AssertIPAddressesAreBanned(int failCount1 = -1, int failCount2 = -1)
        {
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ip1, out _));
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ip2, out _));
            Assert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
            Assert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
            failCount1 = (failCount1 < 0 ? info1.Count : failCount1);
            failCount2 = (failCount2 < 0 ? info2.Count : failCount2);
            Assert.AreEqual(failCount1, e1.FailedLoginCount);
            Assert.AreEqual(failCount2, e2.FailedLoginCount);
            Assert.AreEqual(IPBanDB.IPAddressState.Active, e1.State);
            Assert.AreEqual(IPBanDB.IPAddressState.Active, e2.State);
        }

        private void AssertIPAddressesAreNotBanned(bool exists1 = false, bool exists2 = false)
        {
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ip1, out _));
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ip2, out _));
            if (exists1)
            {
                Assert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                Assert.AreNotEqual(IPBanDB.IPAddressState.Active, e1.State);
            }
            else
            {
                Assert.IsFalse(service.DB.TryGetIPAddress(ip1, out _));
            }
            if (exists2)
            {
                Assert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
                Assert.AreNotEqual(IPBanDB.IPAddressState.Active, e2.State);
            }
            else
            {
                Assert.IsFalse(service.DB.TryGetIPAddress(ip2, out _));
            }
        }

        private void AssertNoIPInDB()
        {
            Assert.IsFalse(service.DB.TryGetIPAddress(ip1, out _));
            Assert.IsFalse(service.DB.TryGetIPAddress(ip2, out _));
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
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info3 });
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
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked("44.55.66.77"));
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
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked("33.32.31.30"));
            }
        }

        [Test]
        public void TestBanIPAddressExternal()
        {
            // add the external event to the service
            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent("11.11.12.13", "TestDomain\\TestUser", "RDP", 0, IPAddressEventType.Blocked, new DateTime(2020, 01, 01))
            });
            service.RunCycleAsync().Sync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("11.11.12.13", out _));
            Assert.IsTrue(service.DB.TryGetIPAddress("11.11.12.13", out IPBanDB.IPAddressEntry entry));
            Assert.IsNotNull(entry.BanStartDate);
        }

        [Test]
        public void TestBlockIPAddresesBlockFile()
        {
            // put an ban.txt file in path, service should pick it up and ban the ip addresses
            File.WriteAllLines(service.BlockIPAddressesFileName, new string[] { ip1, ip2 });
            service.RunCycleAsync().Sync();
            AssertIPAddressesAreBanned(0, 0);
        }

        [Test]
        public void TestBlockIPAddressesMethodCall()
        {
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { new IPAddressLogEvent(ip1, string.Empty, string.Empty, 1, IPAddressEventType.Blocked),
                new IPAddressLogEvent(ip2, string.Empty, string.Empty, 1, IPAddressEventType.Blocked) });

            // this should block the ip addresses
            service.RunCycleAsync().Sync();
            AssertIPAddressesAreBanned(0, 0);
        }

        [Test]
        public void TestUnblockIPAddresesUnblockFile()
        {
            AddFailedLogins();
            AssertIPAddressesAreBanned();

            // put an unban.txt file in path, service should pick it up
            File.WriteAllLines(service.UnblockIPAddressesFileName, new string[] { ip1, ip2 });

            // this should un ban the ip addresses
            service.RunCycleAsync().Sync();

            AssertIPAddressesAreNotBanned();
            AssertNoIPInDB();
        }

        [Test]
        public void TestUnblockIPAddressesMethodCall()
        {
            AddFailedLogins();
            AssertIPAddressesAreBanned();

            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { new IPAddressLogEvent(ip1, string.Empty, string.Empty, 1, IPAddressEventType.Unblocked),
                new IPAddressLogEvent(ip2, string.Empty, string.Empty, 1, IPAddressEventType.Unblocked) });

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
                    Assert.IsTrue(service.DB.TryGetIPAddress("88.88.88.88", out IPBanDB.IPAddressEntry entry));
                    Assert.AreEqual("User1", entry.UserName);
                    Assert.AreEqual("SSH", entry.Source);
                }

                IPBanService.UtcNow += TimeSpan.FromMinutes(5.0);
            }
            service.RunCycleAsync().Sync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("88.88.88.88", out _));

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
                    Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
                }
                finally
                {
                    ExtensionMethods.DirectoryDeleteWithRetry(Path.GetDirectoryName(file));
                    using EventLog appLog = new("Application", System.Environment.MachineName);
                    appLog.Clear();
                }
            }
        }

        [Test]
        public void TestExtraFirewallRules()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSetting(xml, "FirewallRules", @"
                    ReddisAllowIP;allow;10.0.0.1,10.0.0.2,192.168.1.168/24;6379;.
                    WebOnly;block;0.0.0.0/1,128.0.0.0/1,::/1,8000::/1;22,80,443,3389;^(?:(?!Windows).)+$");
            }, out string newConfig);

            List<string> rules = service.Firewall.GetRuleNames().ToList();
            string reddisRule = service.Firewall.RulePrefix + "EXTRA_ReddisAllowIP";
            string webRule = service.Firewall.RulePrefix + "EXTRA_WebOnly";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // on Windows, block is the default, so only the allow rules should show up
                Assert.IsTrue(rules.Exists((s) => s.StartsWith(reddisRule)));
                Assert.IsFalse(rules.Exists((s) => s.StartsWith(webRule)));
                Assert.AreEqual(1, service.Config.ExtraRules.Count);
                IPBanFirewallRule rule1 = service.Config.ExtraRules[0];
                string regexString = rule1.ToString();
                Assert.AreEqual("EXTRA_ReddisAllowIP;allow;10.0.0.1/32,10.0.0.2/32,192.168.1.0/24;6379;.", regexString);
            }
            else
            {
                // on Linux, both rules are needed
                Assert.AreEqual(2, service.Config.ExtraRules.Count);
                Assert.IsTrue(rules.Exists((s) => s.StartsWith(reddisRule)));
                Assert.IsTrue(rules.Exists((s) => s.StartsWith(webRule)));
                IPBanFirewallRule rule1 = service.Config.ExtraRules[0];
                IPBanFirewallRule rule2 = service.Config.ExtraRules[1];
                string regexString1 = rule1.ToString();
                string regexString2 = rule2.ToString();
                Assert.AreEqual("EXTRA_ReddisAllowIP;allow;10.0.0.1/32,10.0.0.2/32,192.168.1.0/24;6379;.", regexString1);
                Assert.AreEqual("EXTRA_WebOnly;block;0.0.0.0/1,128.0.0.0/1,::/1,8000::/1;22,80,443,3389;^(?:(?!Windows).)+$", regexString2);
            }
        }

        [Test]
        public async Task TestUserNameBan()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSetting(xml, "Blacklist", "NaughtyUserName");
            }, out string newConfig);

            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                // a single failed login with a non-blacklisted user name should not get banned
                new IPAddressLogEvent("99.99.99.99", "Good User Name", "RDP", 1, IPAddressEventType.FailedLogin),

                // a single failed login with a blacklisted user name should get banned
                new IPAddressLogEvent("99.99.99.90", "NaughtyUserName", "RDP", 1, IPAddressEventType.FailedLogin)
            });
            await service.RunCycleAsync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestUserNameWhitelistRegexBan()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSetting(xml, "UserNameWhitelistRegex", "ftp_[0-9]+");
            }, out string newConfig);

            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                // a single failed login with a non-blacklisted user name should not get banned
                new IPAddressLogEvent("99.99.99.99", "ftp_1", "RDP", 1, IPAddressEventType.FailedLogin),

                // a single failed login with a failed user name whitelist regex should get banned
                new IPAddressLogEvent("99.99.99.90", "NaughtyUserName", "RDP", 1, IPAddressEventType.FailedLogin)
            });
            await service.RunCycleAsync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestUserNameWhitelistBan()
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSetting(xml, "UserNameWhitelist", "OnlyMe");
            }, out string newConfig);

            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                // should ban, we have a user name whitelist
                new IPAddressLogEvent("99.99.99.90", "ftp_1", "RDP", 1, IPAddressEventType.FailedLogin),

                // should not ban after 19 attempts, user is whitelisted
                new IPAddressLogEvent("99.99.99.99", "onlyme", "RDP", 19, IPAddressEventType.FailedLogin)
            });
            await service.RunCycleAsync();

            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.90", out _));
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
        }

        [Test]
        public async Task TestNoInternalFailedLoginsOrBans()
        {
            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent("10.11.12.13", "TestUser", "RDP", 9, IPAddressEventType.FailedLogin)
            });
            await service.RunCycleAsync();
            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent("10.11.12.13", "TestUser", "RDP", 9, IPAddressEventType.FailedLogin)
            });
            await service.RunCycleAsync();

            Assert.IsFalse(service.Firewall.IsIPAddressBlocked("10.11.12.13"));
        }

        [Test]
        public async Task TestBanOverrideFailedLoginThreshold()
        {
            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent("11.11.12.13", "TestUser", "RDP", 9, IPAddressEventType.FailedLogin,
                    new DateTime(2020, 01, 01), failedLoginThreshold: 10)
            });

            await service.RunCycleAsync();
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked("10.11.12.13"));

            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent("11.11.12.13", "TestUser", "RDP", 1, IPAddressEventType.FailedLogin,
                    new DateTime(2020, 01, 01), failedLoginThreshold: 10)
            });

            await service.RunCycleAsync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("11.11.12.13"));
        }

        private async Task TestMultipleBanTimespansAsync(bool resetFailedLogin)
        {
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                xml = IPBanConfig.ChangeConfigAppSetting(xml, "BanTime", "00:00:01:00,00:00:02:00,00:00:03:00");
                xml = IPBanConfig.ChangeConfigAppSetting(xml, "ResetFailedLoginCountForUnbannedIPAddresses", resetFailedLogin.ToString());
                return xml;
            }, out string newConfig);

            Assert.AreEqual(3, service.Config.BanTimes.Length);
            Assert.AreEqual(resetFailedLogin, service.Config.ResetFailedLoginCountForUnbannedIPAddresses);
            for (int i = 1; i <= 3; i++)
            {
                Assert.AreEqual(TimeSpan.FromMinutes(i), service.Config.BanTimes[i - 1]);
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

                    Assert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                    Assert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));

                    // i == 3 means wrap around from 3 minutes back to 1 minute
                    TimeSpan expectedBanDuration = (i < 3 ? expectedBanDuration = TimeSpan.FromMinutes(i + 1) : TimeSpan.FromMinutes(1.0));
                    Assert.AreEqual(expectedBanDuration, e1.BanEndDate - e1.BanStartDate);
                    Assert.AreEqual(expectedBanDuration, e2.BanEndDate - e2.BanStartDate);
                    if (resetFailedLogin)
                    {
                        Assert.AreEqual(0, e1.FailedLoginCount);
                        Assert.AreEqual(0, e2.FailedLoginCount);
                    }
                    else
                    {
                        Assert.AreNotEqual(0, e1.FailedLoginCount);
                        Assert.AreNotEqual(0, e2.FailedLoginCount);
                    }
                }
                else
                {
                    // the cycle will run and remove the expired ip first as they have finished the loop through the ban times, they should all have a single failed login count
                    AddFailedLogins(1);

                    // ips should exist but not be banned
                    AssertIPAddressesAreNotBanned(true, true);
                    Assert.IsTrue(service.DB.TryGetIPAddress(ip1, out IPBanDB.IPAddressEntry e1));
                    Assert.IsTrue(service.DB.TryGetIPAddress(ip2, out IPBanDB.IPAddressEntry e2));
                    Assert.IsNull(e1.BanStartDate);
                    Assert.IsNull(e2.BanStartDate);
                    Assert.IsNull(e1.BanEndDate);
                    Assert.IsNull(e2.BanEndDate);
                    Assert.AreEqual(1, e1.FailedLoginCount);
                    Assert.AreEqual(1, e2.FailedLoginCount);

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
                    Assert.IsTrue(service.DB.TryGetIPAddress(ip1, out e1));
                    Assert.IsTrue(service.DB.TryGetIPAddress(ip2, out e2));
                    TimeSpan expectedBanDuration = TimeSpan.FromMinutes(1.0);
                    Assert.AreEqual(expectedBanDuration, e1.BanEndDate - e1.BanStartDate);
                    Assert.AreEqual(expectedBanDuration, e2.BanEndDate - e2.BanStartDate);
                    if (resetFailedLogin)
                    {
                        Assert.AreEqual(0, e1.FailedLoginCount);
                        Assert.AreEqual(0, e2.FailedLoginCount);
                    }
                    else
                    {
                        Assert.AreEqual(info1.Count + 1, e1.FailedLoginCount);
                        Assert.AreEqual(info2.Count + 1, e2.FailedLoginCount);
                    }
                }
            }
        }

        private class ExternalBlocker : IIPBanDelegate
        {
            private readonly IIPBanService service;

            public ExternalBlocker(IIPBanService service)
            {
                this.service = service;
            }

            public Task LoginAttemptFailed(string ipAddress, string source, string userName, string machineGuid, string osName, string osVersion, int count, DateTime timestamp)
            {
                var events = new IPAddressLogEvent[] { new IPAddressLogEvent(ipAddress, userName, source, count, IPAddressEventType.Blocked, IPBanService.UtcNow, true) };
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
                xml = IPBanConfig.ChangeConfigAppSetting(xml, "BanTime", "00:00:01:00,00:00:05:00,00:00:15:00,89:00:00:00");
                xml = IPBanConfig.ChangeConfigAppSetting(xml, "ResetFailedLoginCountForUnbannedIPAddresses", resetFailedLogin.ToString());
                return xml;
            }, out string newConfig);
            Assert.AreEqual(4, service.Config.BanTimes.Length);

            // send a block event, should get banned for 1 minute
            IPBanService.UtcNow = new DateTime(2020, 1, 1, 1, 1, 1, DateTimeKind.Utc);

            for (int i = 0; i < 2; i++)
            {
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // run cycle again, should get pinged by external blocker and ip should be blocked
                await service.RunCycleAsync();
                Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                Assert.IsTrue(service.DB.TryGetBanDates(ipAddress, out KeyValuePair<DateTime?, DateTime?> banDates));
                Assert.AreEqual(IPBanService.UtcNow, banDates.Key);
                Assert.AreEqual(IPBanService.UtcNow.AddMinutes(1.0), banDates.Value);

                // short step, should still be blocked
                IPBanService.UtcNow += TimeSpan.FromSeconds(1.0);
                await service.RunCycleAsync();
                Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));

                IPBanService.UtcNow += TimeSpan.FromMinutes(1.0);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // send a fail login event, should get banned for 5 minutes
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

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

                Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                Assert.IsTrue(service.DB.TryGetBanDates(ipAddress, out banDates));
                Assert.AreEqual(savedBanDate, banDates.Key);
                Assert.AreEqual(savedBanDate.AddMinutes(5.0), banDates.Value);

                IPBanService.UtcNow += TimeSpan.FromMinutes(20.0);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // send a failed login event, should get banned for 15 minutes
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // cycle again, blocker will ban
                await service.RunCycleAsync();
                Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                Assert.IsTrue(service.DB.TryGetBanDates(ipAddress, out banDates));
                Assert.AreEqual(IPBanService.UtcNow, banDates.Key);
                Assert.AreEqual(IPBanService.UtcNow.AddMinutes(15.0), banDates.Value);

                IPBanService.UtcNow += TimeSpan.FromMinutes(30.0);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // send a block event, should get banned for 89 days
                events[0] = new IPAddressLogEvent(ipAddress, userName, source, 1, type, IPBanService.UtcNow);
                service.AddIPAddressLogEvents(events);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));

                // cycle again, blocker will ban
                await service.RunCycleAsync();
                Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ipAddress));
                Assert.IsTrue(service.DB.TryGetBanDates(ipAddress, out banDates));
                Assert.AreEqual(IPBanService.UtcNow, banDates.Key);
                Assert.AreEqual(IPBanService.UtcNow.AddDays(89.0), banDates.Value);

                IPBanService.UtcNow += TimeSpan.FromDays(91.0);
                await service.RunCycleAsync();
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ipAddress));
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
        }

        [Test]
        public async Task TestFailedAndSuccessLoginFromSameIPAddress()
        {
            await service.RunCycleAsync();

            string ip = "99.88.77.66";

            // we should not do failed login or ban for ip address that had a success login from same ip in the same cycle
            for (int i = 0; i < 10; i++)
            {
                service.AddIPAddressLogEvents(new IPAddressLogEvent[]
                {
                    // fail login
                    new IPAddressLogEvent(ip, "user1", "RDP", 1, IPAddressEventType.FailedLogin),

                    // success login
                    new IPAddressLogEvent(ip, "user1", "RDP", 1, IPAddressEventType.SuccessfulLogin),
                });
            }

            await service.RunCycleAsync();

            Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ip, out _));
        }

        [Test]
        public async Task TestFailedLoginsClearOnSuccessfulLogin()
        {
            // turn on clear failed logins upon success login
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSetting(xml, nameof(IPBanConfig.ClearFailedLoginsOnSuccessfulLogin), "true");
            }, out string newConfig);

            string ip = "99.88.77.66";
            for (int i = 0; i < 2; i++)
            {
                service.AddIPAddressLogEvents(new IPAddressLogEvent[]
                {
                    // fail login
                    new IPAddressLogEvent(ip, "user1", "RDP", 1, IPAddressEventType.FailedLogin),
                });
            }

            await service.RunCycleAsync();

            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent(ip, "user1", "RDP", 1, IPAddressEventType.SuccessfulLogin),
            });

            await service.RunCycleAsync();

            Assert.IsFalse(service.DB.TryGetIPAddress(ip, out _));
        }

        [Test]
        public async Task TestFailedLoginsDoesNotClearOnSuccessfulLogin()
        {
            await service.RunCycleAsync();

            string ip = "99.88.77.66";
            for (int i = 0; i < 2; i++)
            {
                service.AddIPAddressLogEvents(new IPAddressLogEvent[]
                {
                    // fail login
                    new IPAddressLogEvent(ip, "user1", "RDP", 1, IPAddressEventType.FailedLogin),
                });
            }

            await service.RunCycleAsync();

            service.AddIPAddressLogEvents(new IPAddressLogEvent[]
            {
                new IPAddressLogEvent(ip, "user1", "RDP", 1, IPAddressEventType.SuccessfulLogin),
            });

            await service.RunCycleAsync();

            Assert.IsTrue(service.DB.TryGetIPAddress(ip, out _));
        }

        private void RunConfigBanTest(string key, string value, string banIP, string noBanIP, int noBanIPCount = 999)
        {
            // turn on clear failed logins upon success login
            using IPBanConfig.TempConfigChanger configChanger = new(service, xml =>
            {
                return IPBanConfig.ChangeConfigAppSetting(xml, key, value);
            }, out string newConfig);

            List<IPAddressLogEvent> events = new()
            {
                new IPAddressLogEvent(banIP, "user1", "RDP", 999, IPAddressEventType.FailedLogin)
            };
            if (!string.IsNullOrWhiteSpace(noBanIP))
            {
                events.Add(new IPAddressLogEvent(noBanIP, "user2", "RDP", noBanIPCount, IPAddressEventType.FailedLogin));
            }
            service.AddIPAddressLogEvents(events);

            // process failed logins
            service.RunCycleAsync().Sync();

            Assert.IsTrue(service.Firewall.IsIPAddressBlocked(banIP, out _));
            Assert.IsTrue(service.DB.TryGetIPAddress(banIP, out IPBanDB.IPAddressEntry e1));
            Assert.AreEqual(e1.FailedLoginCount, 999);
            if (!string.IsNullOrWhiteSpace(noBanIP))
            {
                Assert.IsFalse(service.Firewall.IsIPAddressBlocked(noBanIP, out _));
                if (noBanIPCount > 0)
                {
                    Assert.IsTrue(service.DB.TryGetIPAddress(noBanIP, out IPBanDB.IPAddressEntry e2));
                    Assert.AreEqual(e2.FailedLoginCount, noBanIPCount);
                }
                else
                {
                    Assert.IsFalse(service.DB.TryGetIPAddress(noBanIP, out _));
                }
            }
        }
    }
}
