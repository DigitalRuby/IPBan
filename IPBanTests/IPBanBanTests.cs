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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

using DigitalRuby.IPBan;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanBanTests
    {
        private const string ip1 = "99.99.99.97";
        private const string ip2 = "99.99.99.98";
        private const string ip3 = "99.99.99.99";
        private static readonly IPAddressLogEvent info1 = new IPAddressLogEvent(ip1, "test_user", "RDP", 98, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info2 = new IPAddressLogEvent(ip2, "test_user2", "SSH", 99, IPAddressEventType.FailedLogin);
        private static readonly IPAddressLogEvent info3 = new IPAddressLogEvent(ip1, "test_user", "RDP", 1, IPAddressEventType.FailedLogin);

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
            service.RunCycle().Sync();
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
            service.RunCycle().Sync();

            AssertIPAddressesAreNotBanned();

            // add a single failed login, should not cause a block
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info3 });
            service.RunCycle().Sync();
            AssertIPAddressesAreNotBanned(true, false);
        }

        [Test]
        public void TestBlockIPAddresesBlockFile()
        {
            // put an ban.txt file in path, service should pick it up and ban the ip addresses
            File.WriteAllLines(service.BlockIPAddressesFileName, new string[] { ip1, ip2 });
            service.RunCycle().Sync();
            AssertIPAddressesAreBanned(0, 0);
        }

        [Test]
        public void TestBlockIPAddressesMethodCall()
        {
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { new IPAddressLogEvent(ip1, string.Empty, string.Empty, 1, IPAddressEventType.Blocked),
                new IPAddressLogEvent(ip2, string.Empty, string.Empty, 1, IPAddressEventType.Blocked) });

            // this should block the ip addresses
            service.RunCycle().Sync();
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
            service.RunCycle().Sync();

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
            service.RunCycle().Sync();

            AssertIPAddressesAreNotBanned();
            AssertNoIPInDB();
        }

        [Test]
        public void TestPlugin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // prime Linux log files
                IPBanPlugin.IPBanLoginFailed("SSH", "User1", "78.88.88.88");
                foreach (IPBanLogFileScanner toParse in service.LogFilesToParse)
                {
                    toParse.PingFiles();
                }
            }
            service.RunCycle().Sync();
            for (int i = 0; i < 5; i++)
            {
                IPBanPlugin.IPBanLoginFailed("SSH", "User1", "88.88.88.88");
                service.RunCycle().Sync();

                // attempt to read failed logins, if they do not match, sleep a bit and try again
                for (int j = 0; j < 10 && (!service.DB.TryGetIPAddress("88.88.88.88", out IPBanDB.IPAddressEntry e) || e.FailedLoginCount != i + 1); j++)
                {
                    System.Threading.Thread.Sleep(100);
                    foreach (IPBanLogFileScanner toParse in service.LogFilesToParse)
                    {
                        toParse.PingFiles();
                    }
                    service.RunCycle().Sync();
                }
                IPBanService.UtcNow += TimeSpan.FromMinutes(5.0);
            }
            service.RunCycle().Sync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("88.88.88.88", out _));

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                File.Delete($"/var/log/ipbancustom_{IPBanPlugin.ProcessName}.log");
            }

            // by default, Windows plugin goes to event viewer, we want to also make sure custom log files work on Windows
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // prime log file to parse
                string file = @"C:/IPBanCustomLogs/ipbancustom_test.log";
                Directory.CreateDirectory(Path.GetDirectoryName(file));
                File.WriteAllText(file, "awerfoajwerp jaeowr paojwer " + Environment.NewLine);
                service.RunCycle().Sync();
                System.Threading.Thread.Sleep(100);
                foreach (IPBanLogFileScanner toParse in service.LogFilesToParse)
                {
                    toParse.PingFiles();
                }
                string data = "ipban failed login, ip address: 99.99.99.99, source: SSH, user: User2" + Environment.NewLine;
                for (int i = 0; i < 5; i++)
                {
                    File.AppendAllText(file, data);
                    IPBanService.UtcNow += TimeSpan.FromMinutes(5.0);
                    foreach (IPBanLogFileScanner toParse in service.LogFilesToParse)
                    {
                        toParse.PingFiles();
                    }

                    // attempt to read failed logins, if they do not match, sleep a bit and try again
                    for (int j = 0; j < 10 && (!service.DB.TryGetIPAddress("99.99.99.99", out IPBanDB.IPAddressEntry e) || e.FailedLoginCount != i + 1); j++)
                    {
                        System.Threading.Thread.Sleep(100);
                        service.RunCycle().Sync();
                    }
                    service.RunCycle().Sync();
                }
                try
                {
                    Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.99", out _));
                }
                finally
                {
                    File.Delete(file);
                    Directory.Delete(Path.GetDirectoryName(file));
                    using (EventLog appLog = new EventLog("Application", System.Environment.MachineName))
                    {
                        appLog.Clear();
                    }
                }
            }
        }

        private void TestMultipleBanTimespans(bool resetFailedLogin)
        {
            string config = File.ReadAllText(service.ConfigFilePath);
            string newConfig = IPBanConfig.ChangeConfigAppSetting(config, "BanTime", "00:00:01:00,00:00:02:00,00:00:03:00");
            newConfig = IPBanConfig.ChangeConfigAppSetting(newConfig, "ResetFailedLoginCountForUnbannedIPAddresses", resetFailedLogin.ToString());
            File.WriteAllText(service.ConfigFilePath, newConfig);
            try
            {
                service.RunCycle().Sync();
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
                    service.RunCycle().Sync();

                    if (i < 3)
                    {
                        if (i > 0)
                        {
                            AssertIPAddressesAreNotBanned(true, true);
                        }

                        AddFailedLogins((i == 0 ? -1 : 1));

                        if (resetFailedLogin)
                        {
                            if (i > 0)
                            {
                                // after one fail login, should not be banned
                                AssertIPAddressesAreNotBanned(true, true);
                            }

                            // add more failed logins
                            AddFailedLogins();

                            // now they should be banned, fail login counts are reset upon ban
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
            finally
            {
                // restore config
                File.WriteAllText(service.ConfigFilePath, config);
            }
        }

        [Test]
        public void TestMultipleBanTimespansResetFailedLoginCount()
        {
            TestMultipleBanTimespans(true);
        }

        [Test]
        public void TestMultipleBanTimespansNoResetFailedLoginCount()
        {
            TestMultipleBanTimespans(false);
        }
    }
}
