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

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanOSTests
    {
        [Test]
        public void TestOSIsRecognized()
        {
            Assert.IsTrue(OSUtility.Name == OSUtility.Windows || OSUtility.Name == OSUtility.Linux ||
                OSUtility.Name == OSUtility.Mac);
        }

        [Test]
        public void TestSystemMemory()
        {
            Assert.IsTrue(DefaultSystemMemory.Instance.GetSystemMemory(out long total, out long avail));
            Assert.IsTrue(total >= avail);
            Assert.IsTrue(total > 0);
            Assert.IsTrue(avail > 0);
        }

        [Test]
        public void TestGetMacAddress()
        {
            string mac = NetworkUtility.GetMacAddress();
            Assert.GreaterOrEqual(12, mac.Length);
        }

        [Test]
        public void TestGetUserNameIsActive()
        {
            bool result = OSUtility.UserIsActive("root");
            Assert.AreEqual(result, OSUtility.UserIsActive("root"));

            result = OSUtility.UserIsActive(Environment.UserName);
            Assert.AreEqual(result, OSUtility.UserIsActive(Environment.UserName));

            // try something not exist, make sure false
            Assert.IsFalse(OSUtility.UserIsActive("asdoijasdoajspdojaspdojaspodjaspodjs"));
        }
    }
}
