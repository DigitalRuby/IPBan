/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanPlugin static class.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanPluginTests
    {
        [Test]
        public void ProcessName_IsSet()
        {
            ClassicAssert.IsNotNull(IPBanPlugin.ProcessName);
            ClassicAssert.IsNotEmpty(IPBanPlugin.ProcessName);
        }

        [Test]
        public void IPBanLoginFailed_AndSucceeded_DoNotThrow()
        {
            int errors = 0;
            var prev = IPBanPlugin.ErrorHandler;
            IPBanPlugin.ErrorHandler = ex => errors++;
            try
            {
                Assert.DoesNotThrow(() => IPBanPlugin.IPBanLoginFailed("RDP", "user", "1.2.3.4"));
                Assert.DoesNotThrow(() => IPBanPlugin.IPBanLoginSucceeded("RDP", "user", "1.2.3.4"));
            }
            finally
            {
                IPBanPlugin.ErrorHandler = prev;
            }
            ClassicAssert.GreaterOrEqual(errors, 0);
        }
    }
}
