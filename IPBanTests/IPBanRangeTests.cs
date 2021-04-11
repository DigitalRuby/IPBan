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

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanRangeTests
    {
        private static void TestPortRangeAllow(string expected, string message, params PortRange[] ranges)
        {
            string actual = IPBanFirewallUtility.GetPortRangeStringAllow(ranges);
            Assert.AreEqual(expected, actual, message ?? "Invalid port string");
        }

        private static void TestPortRangeBlockExcept(string expected, string message, params PortRange[] ranges)
        {
            string actual = IPBanFirewallUtility.GetBlockPortRangeString(ranges);
            Assert.AreEqual(expected, actual, message ?? "Invalid port string");
        }

        private static void TestFilterIPAddressRangesHelper(IPAddressRange[] expected, string message, IPAddressRange[] filter, params IPAddressRange[] ranges)
        {
            int index = 0;
            foreach (IPAddressRange range in IPBanFirewallUtility.FilterRanges(ranges, filter))
            {
                if (index >= expected.Length)
                {
                    Assert.Fail("Too many filtered results, expected max count of {0}", expected.Length - 1);
                }

                // nunit areequal is strange, it calls enumerators and other crap, why it doesn't just do .Equals is beyond me...
                IPAddressRange existing = expected[index++];
                IPAddressRange actual = range;
                Assert.That(existing.Equals(actual), message);
            }
        }

        [Test]
        public void TestPortStringAllow()
        {
            TestPortRangeAllow(null, "Invalid range should be null", "-1");
            TestPortRangeAllow("80", null, "80");
            TestPortRangeAllow("80,443,1000-1010", null, "80", "443", "1000-1010");
            TestPortRangeAllow("80,443,1000-1010", null, "80", "443", "1000-1010", "999999");
            TestPortRangeAllow("1,2,3,4", null, "4", "3", "2", "1", "3", "2", "1", "3");
        }

        [Test]
        public void TestPortStringBlock()
        {
            TestPortRangeBlockExcept(null, "Invalid range should be null", "-1");
            TestPortRangeBlockExcept("0-24,26-79,81-442,444-65535", null, "25", "80", "443");
            TestPortRangeBlockExcept("0-24,26-79,81-442,444-65535", null, "25", "80", "443", "25", "80", "443");
            TestPortRangeBlockExcept("0-24,1000-1023,1051-65535", null, "25-999", "1024-1050");
            TestPortRangeBlockExcept("0,65535", null, "1-65534");
            TestPortRangeBlockExcept(null, null, "0-65535");
        }

        [Test]
        public void TestFilterIPAddressRanges()
        {
            IPAddressRange[] expected = new IPAddressRange[]
            {
                "1.1.1.1-1.1.1.3",
                "2.2.2.2",
                "3.3.3.1-3.3.3.3",
                "3.3.3.10-3.3.3.15",
                "6.6.6.6-6.6.6.12",
                "6.6.6.18-6.6.6.19",
                "6.6.6.31-6.6.6.98",
                "2620:0:2d0:2df::1-2620:0:2d0:2df::6",
                "2620:0:2d0:2df::78-2620:0:2d0:2df::79"
            };

            IPAddressRange[] filter = new IPAddressRange[]
            {
                "0.0.0.0-1.1.1.0",
                "1.1.1.4-2.2.2.1",
                "2.2.2.3-3.3.3.0",
                "3.3.3.4-3.3.3.9",
                "3.3.3.16-5.5.5.255",
                "6.6.6.13-6.6.6.17",
                "6.6.6.20-6.6.6.30",
                "6.6.6.99-255.255.255.255",
                "2620:0:2d0:2df::7-2620:0:2d0:2df::77"
            };

            IPAddressRange[] ranges = new IPAddressRange[]
            {
                "0.0.0.1-1.1.1.0", // filtered out
                "1.1.1.1-2.2.2.1", // filtered down
                "2.2.2.2-2.2.2.255", // filtered down
                "3.3.3.0-5.5.5.5", // filtered 2x
                "6.6.6.6-7.7.7.7", // filtered 3x
                "10.10.10.10-11.11.11.11", // filtered out
                "2620:0:2d0:2df::1-2620:0:2d0:2df::79" // filtered down
            };

            TestFilterIPAddressRangesHelper(expected, null, filter, ranges);
        }

        [Test]
        public void TestFilterIPAddressRangesNulls()
        {
            TestFilterIPAddressRangesHelper(System.Array.Empty<IPAddressRange>(), null, null, null);
            TestFilterIPAddressRangesHelper(System.Array.Empty<IPAddressRange>(), null, new IPAddressRange[] { "1.1.1.1-2.2.2.2" }, null);
            TestFilterIPAddressRangesHelper(new IPAddressRange[] { "1.1.1.1-2.2.2.2" }, null, null, new IPAddressRange[] { "1.1.1.1-2.2.2.2" });
        }

        [Test]
        public void TestFilterIPAddressRangeFilterNoIntersect()
        {
            TestFilterIPAddressRangesHelper
            (
                new IPAddressRange[] { "1.1.1.1-2.2.2.2" },
                null,
                new IPAddressRange[] { "0.0.0.0-1.1.1.0", "2.2.2.3-2.2.2.255" },
                new IPAddressRange[] { "1.1.1.1-2.2.2.2" }
            );
        }

        [Test]
        public void TestFilterAllIPV4()
        {
            TestFilterIPAddressRangesHelper
            (
                System.Array.Empty<IPAddressRange>(),
                null,
                new IPAddressRange[] { "0.0.0.0-255.255.255.255" },
                new IPAddressRange[] { "0.0.0.0-2.2.2.2", "5.5.5.5-6.6.6.6" }
            );
        }

        [Test]
        public void TestIPAddressIsLocalHost()
        {
            Assert.IsTrue(System.Net.IPAddress.Parse("127.0.0.1").IsLocalHost());
            Assert.IsTrue(System.Net.IPAddress.Parse("::1").IsLocalHost());
            Assert.IsFalse(System.Net.IPAddress.Parse("127.0.0.2").IsLocalHost());
            Assert.IsFalse(System.Net.IPAddress.Parse("::2").IsLocalHost());
            Assert.IsFalse(((System.Net.IPAddress)null).IsLocalHost());
        }

        [Test]
        public void TestTryCreateIPAddressRangeFromIPAddresses()
        {
            var ip1 = System.Net.IPAddress.Parse("1.1.1.1");
            var ip2 = System.Net.IPAddress.Parse("1.1.1.2");
            var ip3 = System.Net.IPAddress.Parse("1.1.1.3");
            var ip4 = System.Net.IPAddress.Parse("1.1.1.4");
            var ip5 = IPAddressRange.Parse("1.1.1.5-1.1.1.10");
            var ip6 = System.Net.IPAddress.Parse("255.255.255.254");
            var ip7 = System.Net.IPAddress.Parse("255.255.255.255");

            IPAddressRange range = IPAddressRange.TryCreateFromIPAddressRanges(ip1, ip2, ip3, ip4);
            Assert.AreEqual("1.1.1.1-1.1.1.4", range.ToString());
            range = IPAddressRange.TryCreateFromIPAddresses(ip1, ip2, ip3, ip4);
            Assert.AreEqual("1.1.1.1-1.1.1.4", range.ToString());

            range = IPAddressRange.TryCreateFromIPAddressRanges(ip1, ip2, ip3, ip4, ip5);
            Assert.AreEqual("1.1.1.1-1.1.1.10", range.ToString());

            range = IPAddressRange.TryCreateFromIPAddressRanges(ip6, ip7);
            Assert.AreEqual("255.255.255.254-255.255.255.255", range.ToString());
            range = IPAddressRange.TryCreateFromIPAddresses(ip6, ip7);
            Assert.AreEqual("255.255.255.254-255.255.255.255", range.ToString());

            range = IPAddressRange.TryCreateFromIPAddressRanges(ip1, ip3);
            Assert.IsNull(range);
            range = IPAddressRange.TryCreateFromIPAddresses(ip1, ip3);
            Assert.IsNull(range);
        }
    }
}
