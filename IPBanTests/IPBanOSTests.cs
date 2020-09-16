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
    }
}
