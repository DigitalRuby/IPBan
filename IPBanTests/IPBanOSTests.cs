using DigitalRuby.IPBanCore;

using NUnit.Framework;

using System;

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
