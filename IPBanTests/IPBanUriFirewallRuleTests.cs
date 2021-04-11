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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanUriFirewallRuleTests : IIsWhitelisted, IHttpRequestMaker
    {
        private static readonly IPAddressRange range1 = IPAddressRange.Parse("99.99.99.99");
        private static readonly IPAddressRange range2 = IPAddressRange.Parse("100.100.100.100/31");
        private static readonly IPAddressRange range3 = IPAddressRange.Parse("89.99.99.99");

        private readonly IPBanMemoryFirewall memoryFirewall = new();

        private static string GetTestFile()
        {
            return $"# Comment\n{range1.ToCidrString()}\n\n{range2.ToCidrString()}\n{range3.ToCidrString()}\n";
        }

        private async Task TestFileInternal(string uri)
        {
            string tempFile = (string.IsNullOrWhiteSpace(uri) ? Path.GetTempFileName() : null);
            if (tempFile != null)
            {
                tempFile = tempFile.Replace("\\", "/");
            }
            try
            {
                Uri uriObj = (tempFile == null ? new Uri(uri) : new Uri("file://" + tempFile));
                using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, "TestPrefix", TimeSpan.FromMinutes(1.0), uriObj);
                if (tempFile != null)
                {
                    File.WriteAllText(tempFile, GetTestFile());
                }
                await rule.Update();
                Assert.AreEqual(1, memoryFirewall.GetRuleNames("TestPrefix").ToArray().Length);
                var ranges = memoryFirewall.EnumerateIPAddresses("TestPrefix").ToArray();
                Assert.Contains(range1, ranges);
                Assert.Contains(range2, ranges);
                Assert.Contains(range3, ranges);
                Assert.AreEqual(0, memoryFirewall.EnumerateAllowedIPAddresses().ToArray().Length);
            }
            finally
            {
                if (tempFile != null)
                {
                    File.Delete(tempFile);
                }
            }
        }

        public Task<byte[]> MakeRequestAsync(Uri uri, string postJson = null, IEnumerable<KeyValuePair<string, object>> headers = null,
            CancellationToken cancelToken = default)
        {
            return Task.FromResult(Encoding.UTF8.GetBytes(GetTestFile()));
        }

        [SetUp]
        public void Setup()
        {
            memoryFirewall.Truncate();
        }

        [Test]
        public async Task TestNoOp()
        {
            using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, "TestPrefix", TimeSpan.FromMinutes(1.0), new Uri("file://c:/temp/qweoqpwejqowtempfirewall.txt"));
            await rule.Update();
            Assert.AreEqual(0, memoryFirewall.EnumerateIPAddresses().ToArray().Length);
        }

        [Test]
        public async Task TestFile()
        {
            await TestFileInternal(null);
        }

        [Test]
        public async Task TestUrl()
        {
            await TestFileInternal("http://localhost");
        }

        public bool IsWhitelisted(string entry)
        {
            return memoryFirewall.IsIPAddressAllowed(entry);
        }

        public bool IsWhitelisted(IPAddressRange range)
        {
            return memoryFirewall.IsIPAddressAllowed(range.ToString());
        }
    }
}
