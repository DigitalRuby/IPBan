/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the static helpers on IPBanConfig: GetConfigAppSetting,
ChangeConfigAppSetting, ChangeConfigAppSettingAndGetXml, MergeXml,
ValidateFirewallUriRules, ChangeConfigEventViewer.
*/

using System;
using System.Threading.Tasks;
using System.Xml;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanConfigStaticHelperTests
    {
        [Test]
        public void GetConfigAppSetting_NullOrEmptyKey_ReturnsNull()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration><appSettings><add key='foo' value='bar' /></appSettings></configuration>");
            ClassicAssert.IsNull(IPBanConfig.GetConfigAppSetting(doc, null));
            ClassicAssert.IsNull(IPBanConfig.GetConfigAppSetting(doc, ""));
            ClassicAssert.IsNull(IPBanConfig.GetConfigAppSetting(doc, "  "));
        }

        [Test]
        public void GetConfigAppSetting_MissingKey_ReturnsNull()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration><appSettings><add key='foo' value='bar' /></appSettings></configuration>");
            ClassicAssert.IsNull(IPBanConfig.GetConfigAppSetting(doc, "missing"));
        }

        [Test]
        public void GetConfigAppSetting_ExistingKey_ReturnsValue()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration><appSettings><add key='foo' value='bar' /></appSettings></configuration>");
            ClassicAssert.AreEqual("bar", IPBanConfig.GetConfigAppSetting(doc, "foo"));
        }

        [Test]
        public void ChangeConfigAppSetting_UpdatesExisting()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration><appSettings><add key='foo' value='bar' /></appSettings></configuration>");
            IPBanConfig.ChangeConfigAppSetting(doc, "foo", "baz");
            ClassicAssert.AreEqual("baz", IPBanConfig.GetConfigAppSetting(doc, "foo"));
        }

        [Test]
        public void ChangeConfigAppSetting_AddsMissing()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration><appSettings></appSettings></configuration>");
            IPBanConfig.ChangeConfigAppSetting(doc, "newkey", "newval");
            ClassicAssert.AreEqual("newval", IPBanConfig.GetConfigAppSetting(doc, "newkey"));
        }

        [Test]
        public void ChangeConfigAppSetting_CreatesAppSettingsIfMissing()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration></configuration>");
            IPBanConfig.ChangeConfigAppSetting(doc, "k", "v");
            ClassicAssert.AreEqual("v", IPBanConfig.GetConfigAppSetting(doc, "k"));
        }

        [Test]
        public void ChangeConfigAppSetting_NullValue_StoresEmpty()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<configuration><appSettings><add key='foo' value='bar' /></appSettings></configuration>");
            IPBanConfig.ChangeConfigAppSetting(doc, "foo", null);
            ClassicAssert.AreEqual("", IPBanConfig.GetConfigAppSetting(doc, "foo"));
        }

        [Test]
        public void ChangeConfigAppSettingAndGetXml_Roundtrips()
        {
            string xml = "<configuration><appSettings><add key='k' value='old' /></appSettings></configuration>";
            string updated = IPBanConfig.ChangeConfigAppSettingAndGetXml(xml, "k", "new");
            ClassicAssert.IsTrue(updated.Contains("\"new\"") || updated.Contains("'new'"));
        }

        [Test]
        public void MergeXml_NullBaseThrows()
        {
            Assert.Throws<ArgumentException>(() => IPBanConfig.MergeXml(null, "<configuration/>"));
            Assert.Throws<ArgumentException>(() => IPBanConfig.MergeXml(string.Empty, "<configuration/>"));
        }

        [Test]
        public void MergeXml_NullOverride_ReturnsBase()
        {
            var doc = IPBanConfig.MergeXml("<configuration><appSettings><add key='k' value='v' /></appSettings></configuration>", null);
            ClassicAssert.IsNotNull(doc);
            ClassicAssert.AreEqual("v", IPBanConfig.GetConfigAppSetting(doc, "k"));
        }

        [Test]
        public void MergeXml_OverrideAppSetting()
        {
            string baseXml = "<configuration><appSettings><add key='k' value='base' /></appSettings></configuration>";
            string overrideXml = "<configuration><appSettings><add key='k' value='override' /></appSettings></configuration>";
            var merged = IPBanConfig.MergeXml(baseXml, overrideXml);
            ClassicAssert.AreEqual("override", IPBanConfig.GetConfigAppSetting(merged, "k"));
        }

        [Test]
        public void ValidateFirewallUriRules_GoodInput_ReturnsNull()
        {
            string rules = "rule1, 00:01:00, http://example.com/list.txt\n";
            ClassicAssert.IsNull(IPBanConfig.ValidateFirewallUriRules(rules));
        }

        [Test]
        public void ValidateFirewallUriRules_BadTimespan_ReturnsError()
        {
            string rules = "rule1, NOT_A_TS, http://example.com/list.txt\n";
            string err = IPBanConfig.ValidateFirewallUriRules(rules);
            ClassicAssert.IsNotNull(err);
            StringAssert.Contains("timespan", err.ToLowerInvariant());
        }

        [Test]
        public void ValidateFirewallUriRules_BadUri_ReturnsError()
        {
            string rules = "rule1, 00:01:00, NOT_A_URI\n";
            string err = IPBanConfig.ValidateFirewallUriRules(rules);
            ClassicAssert.IsNotNull(err);
            StringAssert.Contains("uri", err.ToLowerInvariant());
        }

        [Test]
        public void ValidateFirewallUriRules_EmptyPrefix_ReturnsError()
        {
            string rules = ", 00:01:00, http://example.com/list.txt\n";
            string err = IPBanConfig.ValidateFirewallUriRules(rules);
            ClassicAssert.IsNotNull(err);
        }

        [Test]
        public void ValidateFirewallUriRules_EmptyInput_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanConfig.ValidateFirewallUriRules(string.Empty));
        }

        [Test]
        public void ChangeConfigEventViewer_AppendsAndDeletes()
        {
            string config = "<configuration><ExpressionsToBlock><Groups></Groups></ExpressionsToBlock></configuration>";
            string newConfig = IPBanConfig.ChangeConfigEventViewer(config, failedLogin: true, delete: false,
                groups: new[] { "<Source>Security</Source>" });
            StringAssert.Contains("Security", newConfig);

            string afterDelete = IPBanConfig.ChangeConfigEventViewer(newConfig, failedLogin: true, delete: true,
                groups: new[] { "<Source>Security</Source>" });
            ClassicAssert.IsFalse(afterDelete.Contains("Security"));
        }

        [Test]
        public void ChangeConfigEventViewer_MissingSection_Throws()
        {
            string config = "<configuration></configuration>";
            Assert.Throws<InvalidOperationException>(() =>
                IPBanConfig.ChangeConfigEventViewer(config, failedLogin: true, delete: false,
                    groups: new[] { "<Source>Security</Source>" }));
        }

        // -------- ParseFirewallUriRules --------

        private sealed class StubTaskRunner : IFirewallTaskRunner
        {
            public Task RunFirewallTask<T>(Func<T, IIPBanFirewall, System.Threading.CancellationToken, Task> action, T state, string name)
                => Task.CompletedTask;
        }

        private sealed class StubWhitelistChecker : IIsWhitelisted
        {
            public bool IsWhitelisted(string entry, out string reason) { reason = null; return false; }
            public bool IsWhitelisted(IPAddressRange range, out string reason) { reason = null; return false; }
        }

        [Test]
        public void ParseFirewallUriRules_GoodInput_ReturnsRules()
        {
            using var fw = new IPBanMemoryFirewall();
            var runner = new StubTaskRunner();
            var checker = new StubWhitelistChecker();
            var maker = DefaultHttpRequestMaker.Instance;
            string rules = "Rule1, 00:01:00, http://example.com/list.txt, 100\nRule2, 00:05:00, http://example.com/list2.txt\n";
            var result = IPBanConfig.ParseFirewallUriRules(rules, fw, runner, checker, maker);
            ClassicAssert.AreEqual(2, result.Count);
            foreach (var r in result) r.Dispose();
        }

        [Test]
        public void ParseFirewallUriRules_BadTimespan_Skipped()
        {
            using var fw = new IPBanMemoryFirewall();
            var runner = new StubTaskRunner();
            var checker = new StubWhitelistChecker();
            var maker = DefaultHttpRequestMaker.Instance;
            string rules = "Rule1, NOT_A_TS, http://example.com/list.txt\n";
            var result = IPBanConfig.ParseFirewallUriRules(rules, fw, runner, checker, maker);
            ClassicAssert.AreEqual(0, result.Count);
        }

        [Test]
        public void ParseFirewallUriRules_BadUri_Skipped()
        {
            using var fw = new IPBanMemoryFirewall();
            var runner = new StubTaskRunner();
            var checker = new StubWhitelistChecker();
            var maker = DefaultHttpRequestMaker.Instance;
            string rules = "Rule1, 00:01:00, NOT_A_URI\n";
            var result = IPBanConfig.ParseFirewallUriRules(rules, fw, runner, checker, maker);
            ClassicAssert.AreEqual(0, result.Count);
        }

        [Test]
        public void ParseFirewallUriRules_EmptyInput_NoRules()
        {
            using var fw = new IPBanMemoryFirewall();
            var runner = new StubTaskRunner();
            var checker = new StubWhitelistChecker();
            var maker = DefaultHttpRequestMaker.Instance;
            var result = IPBanConfig.ParseFirewallUriRules(string.Empty, fw, runner, checker, maker);
            ClassicAssert.AreEqual(0, result.Count);
        }
    }
}
