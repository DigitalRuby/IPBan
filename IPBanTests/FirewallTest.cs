using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using IPBan;

using NUnit.Framework;

namespace IPBanTests
{
    [TestFixture]
    public class FirewallTest
    {
        private static readonly Dictionary<string, string> firewallAndOsType = new Dictionary<string, string>();
        private IIPBanFirewall firewall;

        [SetUp]
        public void TestStart()
        {
            firewall = IPBanFirewallUtility.CreateFirewall(firewallAndOsType, "IPBanTest_");

            // clear all blocks
            firewall.BlockIPAddresses(new string[0]).Sync();
        }

        [TearDown]
        public void TestStop()
        {
            // clear all blocks
            firewall.BlockIPAddresses(new string[0]).Sync();
        }

        [Test]
        public void TestBlock()
        {
            firewall.BlockIPAddresses(new string[] { "99.99.99.99" }).Sync();
            Assert.IsTrue(firewall.IsIPAddressBlocked("99.99.99.99"));
        }

        [Test]
        public void TestFirewallMultipleRules()
        {
            string[] toBlock = new string[512 * 10];
            for (int i = 0; i < toBlock.Length; i++)
            {
                toBlock[i] = "10.10." + ((i & 0xFF00) >> 8) + "." + (i & 0x00FF);
            }
            firewall.BlockIPAddresses(toBlock).Sync();
            string[] bannedIP = firewall.EnumerateBannedIPAddresses().ToArray();
            foreach (string origIP in toBlock)
            {
                Assert.IsTrue(bannedIP.Contains(origIP));
            }
        }

        [Test]
        public void TestIPV6()
        {
            string[] toBlock = new string[] { "fe80::c872:be03:5c94:4af2%8", "192.168.0.20" };
            firewall.BlockIPAddresses(toBlock).Sync();
            string[] bannedIP = firewall.EnumerateBannedIPAddresses().ToArray();
            string[] bannedIP2 = firewall.EnumerateIPAddresses().Select(i => i.Begin.ToString()).ToArray();
            Assert.AreEqual(bannedIP.Length, bannedIP2.Length);
            for (int i = 0; i < bannedIP.Length; i++)
            {
                Assert.AreEqual(bannedIP[i], bannedIP2[i]);
            }
            foreach (string origIP in toBlock)
            {
                if (IPBanFirewallUtility.TryGetFirewallIPAddress(origIP, out string normalizedIP))
                {
                    Assert.IsTrue(bannedIP.Contains(normalizedIP));
                }
                else
                {
                    Assert.Fail("Bad ip: " + origIP);
                }
            }
        }

        [Test]
        public void TestIPV4Conversion()
        {
            uint value = IPBanFirewallUtility.ParseIPV4("192.168.1.123");
            Assert.AreEqual(0x7b01a8c0, value, "ParseIPV4 fail");
            string ip = IPBanFirewallUtility.IPV4ToString(value);
            Assert.AreEqual("192.168.1.123", ip, "IPV4ToString fail");
            value = IPBanFirewallUtility.ParseIPV4("192.168.0.0/24");
            Assert.AreEqual(0x0000a8c0, value, "ParseIPV4 fail");
            ip = IPBanFirewallUtility.IPV4ToString(value);
            Assert.AreEqual("192.168.0.0", ip, "IPV4ToString fail");
        }

        [Test]
        public void TestIPInternal()
        {
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("::1");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("10.0.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("10.255.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("127.0.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("127.255.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("172.16.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("172.31.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("192.168.0.0");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("192.168.255.255");
            Assert.IsTrue(ip.IsInternal());
            ip = IPAddress.Parse("99.99.99.99");
            Assert.IsFalse(ip.IsInternal());
        }
    }
}
