using DigitalRuby.IPBan;

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
            string actual = IPBanFirewallUtility.GetPortRangeStringBlockExcept(ranges);
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
            TestFilterIPAddressRangesHelper(new IPAddressRange[0], null, null, null);
            TestFilterIPAddressRangesHelper(new IPAddressRange[0], null, new IPAddressRange[] { "1.1.1.1-2.2.2.2" }, null);
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
                new IPAddressRange[0],
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
    }
}
