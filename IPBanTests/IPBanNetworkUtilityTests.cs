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
using NUnit.Framework.Legacy;

using System.Net;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanNetworkUtilityTests
    {
        [TestCase("10.0.0.0", true)]
        [TestCase("10.255.255.255", true)]
        [TestCase("127.0.0.1", true)]
        [TestCase("127.255.255.255", true)]
        [TestCase("172.16.0.0", true)]
        [TestCase("172.31.255.255", true)]
        [TestCase("192.168.0.0", true)]
        [TestCase("192.168.255.255", true)]
        [TestCase("99.99.99.99", false)]
        [TestCase("::1", true)]
        [TestCase("2601:642:c001:bdd0:a5d1:8867:a950:14a4", false)]
        public void TestIsInternal(string ip, bool isInternal)
        {
            ClassicAssert.IsTrue(IPAddress.TryParse(ip, out var ipObj));
            ClassicAssert.AreEqual(isInternal, ipObj.IsInternal());
        }
    }
}
