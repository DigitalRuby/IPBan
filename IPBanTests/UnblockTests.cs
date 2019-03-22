using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

using IPBan;

using NUnit.Framework;

namespace IPBanTests
{
    [TestFixture]
    public class UnblockTests
    {
        private const string ip1 = "99.99.99.98";
        private const string ip2 = "99.99.99.99";
        private static readonly IPAddressLogInfo info1 = new IPAddressLogInfo { Count = 98, IPAddress = ip1, Source = "RDP", UserName = "test_user" };
        private static readonly IPAddressLogInfo info2 = new IPAddressLogInfo { Count = 99, IPAddress = ip2, Source = "SSH", UserName = "test_user2" };

        private IPBanService service;

        [SetUp]
        public void Setup()
        {
            // ensure a clean start
            service = IPBanService.CreateAndStartIPBanTestService<IPBanService>();
        }

        [TearDown]
        public void Teardown()
        {
            service.Firewall.BlockIPAddresses(new string[0]);
            service.Dispose();
        }

        private void AddFailedLogins()
        {
            service.AddFailedLogin(info1);
            service.AddFailedLogin(info2);
            service.RunCycle();
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
            Assert.IsNull(service.DB.GetIPAddress(ip1));
            Assert.IsNull(service.DB.GetIPAddress(ip2));
        }

        [Test]
        public void TestUnblockIPAddresesUnblockFile()
        {
            AddFailedLogins();
            AssertFailedLogins();

            // put an unban.txt file in path, service should pick it up
            File.WriteAllLines(service.UnblockIPAddressesFileName, new string[] { ip1, ip2 });

            // this should un ban the ip addresses
            service.RunCycle();

            AssertNoFailedLogins();
        }

        [Test]
        public void TestUnblockIPAddressesMethodCall()
        {
            AddFailedLogins();
            AssertFailedLogins();

            service.UnblockIPAddresses(new string[] { ip1, ip2 });

            // this should un ban the ip addresses
            service.RunCycle();

            AssertNoFailedLogins();
        }
    }
}
