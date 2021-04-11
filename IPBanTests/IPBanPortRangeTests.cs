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
    public class IPBanPortRangeTests
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
    }
}
