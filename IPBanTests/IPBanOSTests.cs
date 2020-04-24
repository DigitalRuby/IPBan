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
            Assert.IsTrue(OSUtility.Instance.Name == OSUtility.Windows || OSUtility.Instance.Name == OSUtility.Linux ||
                OSUtility.Instance.Name == OSUtility.Mac);
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
