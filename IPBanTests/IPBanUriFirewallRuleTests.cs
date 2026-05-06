/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanUriFirewallRuleTests : IFirewallTaskRunner, IIsWhitelisted, IHttpRequestMaker
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
                using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, this, "TestPrefix", TimeSpan.FromMinutes(1.0), uriObj);
                if (tempFile != null)
                {
                    File.WriteAllText(tempFile, GetTestFile());
                }
                await rule.Update();
                ClassicAssert.AreEqual(1, memoryFirewall.GetRuleNames("TestPrefix").ToArray().Length);
                var ranges = memoryFirewall.EnumerateIPAddresses("TestPrefix").ToArray();
                ClassicAssert.Contains(range1, ranges);
                ClassicAssert.Contains(range2, ranges);
                ClassicAssert.Contains(range3, ranges);
                ClassicAssert.AreEqual(0, memoryFirewall.EnumerateAllowedIPAddresses().ToArray().Length);
            }
            finally
            {
                if (tempFile != null)
                {
                    File.Delete(tempFile);
                }
            }
        }

        public Task<byte[]> MakeRequestAsync(Uri uri,
            byte[] postJson = null,
            IEnumerable<KeyValuePair<string, object>> headers = null,
            string method = null,
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
            using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, this, "TestPrefix", TimeSpan.FromMinutes(1.0), new Uri("file://c:/temp/qweoqpwejqowtempfirewall.txt"));
            await rule.Update();
            ClassicAssert.AreEqual(0, memoryFirewall.EnumerateIPAddresses().ToArray().Length);
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

        public bool IsWhitelisted(string entry, out string reason)
        {
            return memoryFirewall.IsIPAddressAllowed(entry, out reason);
        }

        public bool IsWhitelisted(IPAddressRange range, out string reason)
        {
            return memoryFirewall.IsIPAddressAllowed(range.ToString(), out reason);
        }

        public Task RunFirewallTask<T>(Func<T, IIPBanFirewall, CancellationToken, Task> action, T state, string name)
        {
            return action(state, memoryFirewall, default);
        }

        [Test]
        public void ToString_ContainsPrefixIntervalAndUri()
        {
            using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, this, "TestPrefix",
                TimeSpan.FromMinutes(5.0), new Uri("http://example.com/list.txt"));
            string s = rule.ToString();
            StringAssert.Contains("TestPrefix", s);
            StringAssert.Contains("00:05:00", s);
            StringAssert.Contains("example.com", s);
        }

        [Test]
        public void Equals_AndHashCode_BasedOnPrefixIntervalUri()
        {
            using IPBanUriFirewallRule a = new(memoryFirewall, this, this, this, "P",
                TimeSpan.FromMinutes(5.0), new Uri("http://example.com/list.txt"));
            using IPBanUriFirewallRule b = new(memoryFirewall, this, this, this, "P",
                TimeSpan.FromMinutes(5.0), new Uri("http://example.com/list.txt"));
            using IPBanUriFirewallRule c = new(memoryFirewall, this, this, this, "Other",
                TimeSpan.FromMinutes(5.0), new Uri("http://example.com/list.txt"));
            ClassicAssert.IsTrue(a.Equals(b));
            ClassicAssert.IsFalse(a.Equals(c));
            ClassicAssert.IsFalse(a.Equals("not a rule"));
            ClassicAssert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [Test]
        public async Task TestGzipFile()
        {
            string tempFile = Path.GetTempFileName();
            string gzPath = tempFile + ".gz";
            try
            {
                File.Delete(tempFile);
                // Write a gzipped version of the test file content.
                using (var fs = File.Create(gzPath))
                using (var gz = new GZipStream(fs, CompressionMode.Compress))
                using (var sw = new StreamWriter(gz))
                {
                    sw.Write(GetTestFile());
                }
                Uri uriObj = new("file://" + gzPath.Replace("\\", "/"));
                using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, this,
                    "GzPrefix", TimeSpan.FromMinutes(1.0), uriObj);
                await rule.Update();
                ClassicAssert.AreEqual(1, memoryFirewall.GetRuleNames("GzPrefix").ToArray().Length);
            }
            finally
            {
                try { File.Delete(gzPath); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task DeleteRule_RemovesAllRulesUnderPrefix()
        {
            using IPBanUriFirewallRule rule = new(memoryFirewall, this, this, this, "ToDelete",
                TimeSpan.FromMinutes(5.0), new Uri("http://example.com/list.txt"));
            await rule.Update();
            // Some rule(s) should now exist for this prefix
            ClassicAssert.IsTrue(memoryFirewall.GetRuleNames("ToDelete").Any());
            rule.DeleteRule();
            ClassicAssert.IsFalse(memoryFirewall.GetRuleNames("ToDelete").Any());
        }
    }
}
