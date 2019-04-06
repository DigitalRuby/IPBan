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
using System.Net;
using System.Text;

using DigitalRuby.IPBan;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanUnblockTests
    {
        private const string ip1 = "99.99.99.98";
        private const string ip2 = "99.99.99.99";
        private static readonly IPAddressEvent info1 = new IPAddressEvent { Count = 98, IPAddress = ip1, Source = "RDP", UserName = "test_user", Flag = IPAddressEventFlag.FailedLogin };
        private static readonly IPAddressEvent info2 = new IPAddressEvent { Count = 99, IPAddress = ip2, Source = "SSH", UserName = "test_user2", Flag = IPAddressEventFlag.FailedLogin };

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
            service.HandleIPAddressEvent(info1);
            service.HandleIPAddressEvent(info2);
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
            service.RunCycle().Sync();

            AssertNoFailedLogins();
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
        }
    }
}
