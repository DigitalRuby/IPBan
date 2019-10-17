using System;
using System.Linq;
using System.Net;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanMemoryFirewallTests
    {
        [Test]
        public void BasicTest()
        {
            string allowIP = "99.99.99.99";
            string otherIP = "88.88.88.88";
            string ipv6_1 = IPAddress.Parse("2001:db8:85a3:0:0:8a2e:370:7334").ToString();
            string ipv6_2 = IPAddress.Parse("2001:0db8:0a0b:12f0:0000:0000:0000:0001").ToString();
            string[] blockIP = new string[] { allowIP, "100.100.100.100" };
            IPBanMemoryFirewall f = new IPBanMemoryFirewall();
            f.AllowIPAddresses(new string[] { allowIP }).Sync();
            f.BlockIPAddresses(null, blockIP.Concat(new string[] { ipv6_1, ipv6_2 })).Sync();
            IPAddressRange range = new IPAddressRange(IPAddress.Parse(ipv6_2), IPAddress.Parse(ipv6_1));
            f.BlockIPAddresses("TestRule", new IPAddressRange[] { range }, new PortRange[0]);
            string[] banned = f.EnumerateBannedIPAddresses().ToArray();
            IPAddressRange[] banned2 = f.EnumerateIPAddresses("TestRule").ToArray();
            Assert.AreEqual(0, f.GetRuleNames("CB").Count());
            Assert.IsTrue(f.IsIPAddressAllowed(allowIP));
            Assert.IsFalse(f.IsIPAddressBlocked(allowIP, out _));
            Assert.IsFalse(f.IsIPAddressBlocked(otherIP, out _));
            Assert.IsTrue(f.IsIPAddressBlocked(blockIP[1], out _));
            Assert.AreEqual(3, banned.Length);
            Assert.IsTrue(banned.Contains(blockIP[1]));
            Assert.IsTrue(banned.Contains(ipv6_1));
            Assert.IsTrue(banned.Contains(ipv6_2));
            Assert.AreEqual(1, banned2.Length);
            Assert.AreEqual(range.Begin, banned2[0].Begin);
            Assert.AreEqual(range.End, banned2[0].End);
        }
    }
}
