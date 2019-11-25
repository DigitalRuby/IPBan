using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using NUnit.Framework;

using DigitalRuby.IPBanCore;
using System;
using System.IO;
using System.Text;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public class IPBanUriFirewallRuleTests : IIsWhitelisted, IIPBanFirewall, IHttpRequestMaker
    {
        private static readonly IPAddressRange range1 = IPAddressRange.Parse("99.99.99.99");
        private static readonly IPAddressRange range2 = IPAddressRange.Parse("100.100.100.100/31");
        private static readonly IPAddressRange range3 = IPAddressRange.Parse("89.99.99.99");

        private readonly HashSet<IPAddressRange> whiteList = new HashSet<IPAddressRange>();
        private readonly List<IPAddressRange> blockList = new List<IPAddressRange>();
        private string blockRule;
        private int blockCount;
        private int isWhitelistedCount;

        private string GetTestFile()
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
                using IPBanUriFirewallRule rule = new IPBanUriFirewallRule(this, this, this, "TestPrefix", TimeSpan.FromMinutes(1.0), uriObj);
                if (tempFile != null)
                {
                    File.WriteAllText(tempFile, GetTestFile());
                }
                whiteList.Add(range3);
                await rule.Update();
                Assert.AreEqual(1, blockCount);
                Assert.Contains(range1, blockList);
                Assert.Contains(range2, blockList);
                Assert.AreEqual(3, isWhitelistedCount);
                Assert.AreEqual("TestPrefix", blockRule);
            }
            finally
            {
                if (tempFile != null)
                {
                    File.Delete(tempFile);
                }
            }
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            blockRule = ruleNamePrefix;
            blockCount++;
            blockList.AddRange(ranges);
            return Task.FromResult(true);
        }

        public bool IsWhitelisted(IPAddressRange range)
        {
            isWhitelistedCount++;
            return whiteList.Contains(range);
        }

        public Task<byte[]> MakeRequestAsync(Uri uri, string postJson = null, IEnumerable<KeyValuePair<string, object>> headers = null,
            CancellationToken cancelToken = default)
        {
            return Task.FromResult(Encoding.UTF8.GetBytes(GetTestFile()));
        }

        public void Dispose()
        {
        }

        [SetUp]
        public void Setup()
        {
            whiteList.Clear();
            blockList.Clear();
            blockRule = null;
            blockCount = 0;
            isWhitelistedCount = 0;
        }

        [Test]
        public async Task TestNoOp()
        {
            using IPBanUriFirewallRule rule = new IPBanUriFirewallRule(this, this, this, "TestPrefix", TimeSpan.FromMinutes(1.0), new Uri("file://c:/temp/qweoqpwejqowtempfirewall.txt"));
            await rule.Update();
            Assert.AreEqual(0, blockCount);
            Assert.AreEqual(0, isWhitelistedCount);
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
    }
}
