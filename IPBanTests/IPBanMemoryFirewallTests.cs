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
            string allowIP2 = "99.99.99.98";
            string otherIP = "88.88.88.88";
            string ipv6_1 = IPAddress.Parse("2001:db80:85a3:0:0:8a2e:370:7334").ToString();
            string ipv6_2 = IPAddress.Parse("2001:0db8:0a0b:12f0:0000:0000:0000:0001").ToString();
            string[] blockIP = new string[] { allowIP, "100.100.100.100" };
            IPBanMemoryFirewall f = new();
            f.AllowIPAddresses(new string[] { allowIP }).Sync();
            f.AllowIPAddresses("TestRuleAllow", new IPAddressRange[] { IPAddressRange.Parse(allowIP2) }).Sync();
            f.BlockIPAddresses(null, blockIP.Concat(new string[] { allowIP, allowIP2, ipv6_1, ipv6_2 })).Sync();
            IPAddressRange range = new(IPAddress.Parse(ipv6_2), IPAddress.Parse(ipv6_1));
            f.BlockIPAddresses("TestRuleBlock", new IPAddressRange[] { range }, new PortRange[0]);
            string[] banned = f.EnumerateBannedIPAddresses().ToArray();
            IPAddressRange[] banned2 = f.EnumerateIPAddresses("TestRuleBlock").ToArray();
            Assert.AreEqual(0, f.GetRuleNames("CB").Count());
            Assert.IsTrue(f.IsIPAddressAllowed(allowIP));
            Assert.IsFalse(f.IsIPAddressBlocked(allowIP, out _));
            Assert.IsTrue(f.IsIPAddressAllowed(allowIP2));
            Assert.IsFalse(f.IsIPAddressBlocked(allowIP2, out _));
            Assert.IsFalse(f.IsIPAddressBlocked(otherIP, out _));
            Assert.IsTrue(f.IsIPAddressBlocked(blockIP[1], out _));
            Assert.AreEqual(4, banned.Length);
            Assert.IsTrue(banned.Contains(blockIP[1]));
            Assert.IsTrue(banned.Contains(ipv6_1));
            Assert.IsTrue(banned.Contains(ipv6_2));
            Assert.AreEqual(1, banned2.Length);
            Assert.AreEqual(range.Begin, banned2[0].Begin);
            Assert.AreEqual(range.End, banned2[0].End);
        }
    }
}
