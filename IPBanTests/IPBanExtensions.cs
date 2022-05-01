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

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanExtensionTests
    {
        [Test]
        public void TestNetworkGetAllIPAddresses()
        {
            var ips = NetworkUtility.GetAllIPAddresses();
            Assert.IsTrue(ips.Any());
        }

        [Test]
        public void TestNetworkGetPriorityIPAddresses()
        {
            var ips = NetworkUtility.GetPriorityIPAddresses();
            Assert.IsTrue(ips.Any());

            ips = NetworkUtility.GetPriorityIPAddresses(new[]
            {
                "1999:0db8:85a3:0000:0000:8a2e:0370:7334",
                "127.0.0.1",
                "10.0.0.1",
                "44.44.44.44",
                "2003:0db8:85a3:0000:0000:8a2e:0370:7334"
            });
            Assert.IsTrue(ips.Any());

            Assert.AreEqual("44.44.44.44", ips.First().ToString());
        }
    }
}
