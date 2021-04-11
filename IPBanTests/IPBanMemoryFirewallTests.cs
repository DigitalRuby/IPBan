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
            f.BlockIPAddresses("TestRuleBlock", new IPAddressRange[] { range }, Array.Empty<PortRange>());
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
