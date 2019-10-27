using System;
using System.Collections.Generic;
using System.Text;

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
            Assert.IsTrue(IPBanOS.Name == IPBanOS.Windows || IPBanOS.Name == IPBanOS.Linux || IPBanOS.Name == IPBanOS.Mac);
        }

        [Test]
        public void TestSystemMemory()
        {
            long total = -1;
            long avail = -1;
            IPBanOS.GetSystemMemory(ref total, ref avail);
            Assert.IsTrue(total >= avail);
            Assert.IsTrue(total > 0);
            Assert.IsTrue(avail > 0);
        }
    }
}
