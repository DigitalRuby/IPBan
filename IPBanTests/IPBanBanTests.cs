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
        private static readonly IPAddressLogEvent info1 = new IPAddressLogEvent { Count = 98, IPAddress = ip1, Source = "RDP", UserName = "test_user", Type = IPAddressEventType.FailedLogin };
        private static readonly IPAddressLogEvent info2 = new IPAddressLogEvent { Count = 99, IPAddress = ip2, Source = "SSH", UserName = "test_user2", Type = IPAddressEventType.FailedLogin };
        private static readonly IPAddressLogEvent info3 = new IPAddressLogEvent { Count = 1, IPAddress = ip1, Source = "RDP", UserName = "test_user", Type = IPAddressEventType.FailedLogin };

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

        private void AddFailedLogins()
        {
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info1, info2 });
            service.RunCycle().Sync();
        }

        private void AssertFailedLogins()
        {
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ip1));
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked(ip2));
            Assert.AreEqual(info1.Count, service.DB.GetIPAddress(ip1).FailedLoginCount);
            Assert.AreEqual(info2.Count, service.DB.GetIPAddress(ip2).FailedLoginCount);
        }

        private void AssertNoFailedLogins()
        {
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ip1));
            Assert.IsFalse(service.Firewall.IsIPAddressBlocked(ip2));
        }

        private void AssertNoIPInDB()
        {
            Assert.IsNull(service.DB.GetIPAddress(ip1));
            Assert.IsNull(service.DB.GetIPAddress(ip2));
        }

        [Test]
        public void TestBanIPAddresses()
        {
            AddFailedLogins();
            AssertFailedLogins();

            // forget all the bans
            IPBanService.UtcNow += TimeSpan.FromDays(14.0);
            service.RunCycle().Sync();

            AssertNoFailedLogins();

            // add a single failed login, should not cause a block
            service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info3 });
            service.RunCycle().Sync();
            AssertNoFailedLogins();
        }

        [Test]
        public void TestUnblockIPAddresesUnblockFile()
        {
            AddFailedLogins();
            AssertFailedLogins();

            // put an unban.txt file in path, service should pick it up
            File.WriteAllLines(service.UnblockIPAddressesFileName, new string[] { ip1, ip2 });

            // this should un ban the ip addresses
            service.RunCycle().Sync();

            AssertNoFailedLogins();
            AssertNoIPInDB();
        }

        [Test]
        public void TestUnblockIPAddressesMethodCall()
        {
            AddFailedLogins();
            AssertFailedLogins();

            service.UnblockIPAddresses(new string[] { ip1, ip2 });

            // this should un ban the ip addresses
            service.RunCycle().Sync();

            AssertNoFailedLogins();
            AssertNoIPInDB();
        }

        [Test]
        public void TestPlugin()
        {
            service.RunCycle().Sync();
            IPBanPlugin.IPBanLoginFailed("SSH", "User1", "78.88.88.88");
            for (int i = 0; i < 5; i++)
            {
                IPBanPlugin.IPBanLoginFailed("SSH", "User1", "88.88.88.88");
                service.RunCycle().Sync();
                for (int j = 0; j < 10 && service.DB.GetIPAddress("88.88.88.88")?.FailedLoginCount != i + 1; j++)
                {
                    System.Threading.Thread.Sleep(100);
                    service.RunCycle().Sync();
                }
                IPBanService.UtcNow += TimeSpan.FromMinutes(5.0);
            }
            service.RunCycle().Sync();
            Assert.IsTrue(service.Firewall.IsIPAddressBlocked("88.88.88.88"));

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
                    for (int j = 0; j < 10 && service.DB.GetIPAddress("99.99.99.99")?.FailedLoginCount != i + 1; j++)
                    {
                        System.Threading.Thread.Sleep(100);
                        service.RunCycle().Sync();
                    }
                    service.RunCycle().Sync();
                }
                try
                {
                    Assert.IsTrue(service.Firewall.IsIPAddressBlocked("99.99.99.99"));
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
    }
}
