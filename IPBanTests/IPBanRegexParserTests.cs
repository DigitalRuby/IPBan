using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanRegexParserTests
    {
        // ---------- Helpers ----------
        private static Match MatchSingle(string pattern, string text, bool multiline = false)
        {
            var re = IPBanRegexParser.ParseRegex(pattern, multiline);
            ClassicAssert.NotNull(re, "ParseRegex returned null");
            var m = re.Match(text);
            ClassicAssert.IsTrue(m.Success, $"Expected a match for pattern: {pattern}\nText: {text}");
            return m;
        }

        private static void AssertGroup(Match m, string groupName, string expected)
        {
            var g = m.Groups[groupName];
            ClassicAssert.IsTrue(g.Success, $"Expected group '{groupName}' to exist and succeed");
            ClassicAssert.AreEqual(expected, g.Value, $"Group {groupName} mismatch.");
        }

        // ---------- %(__prefix_line)s ----------
        [TestCase("%(__prefix_line)sERROR from <IP>", "Jan  1 00:00:01 host app[123]: ERROR from 1.2.3.4", "1.2.3.4")]
        [TestCase("%(__prefix_line)sLogin failed for <USER> from <HOST>", "Aug 10 12:01:00 x y: Login failed for jeff from 2001:db8::1", "2001:db8::1")]
        public void PrefixMacro_ExpandsAndMatches(string pattern, string text, string expectedIp)
        {
            var m = MatchSingle(pattern, text);
            AssertGroup(m, "ipaddress", expectedIp);
        }

        // ---------- <IP> ----------
        [TestCase("from <IP>", "from 9.8.7.6", "9.8.7.6")]
        [TestCase("from <IP>", "from 2001:db8::1", "2001:db8::1")]
        public void IP_Macro_MatchesIPv4AndIPv6(string pattern, string text, string expected)
        {
            var m = MatchSingle(pattern, text);
            AssertGroup(m, "ipaddress", expected);
        }

        // ---------- <HOST> (defaults: IP-only) ----------
        [TestCase("bad from <HOST>", "bad from 203.0.113.9", "203.0.113.9")]
        [TestCase("bad from <HOST>", "bad from 2001:db8:0:0::2", "2001:db8:0:0::2")]
        public void HOST_Macro_MatchesIpOnly_ByDefault(string pattern, string text, string expected)
        {
            var m = MatchSingle(pattern, text);
            AssertGroup(m, "ipaddress", expected);
        }

        // ---------- <IPV4> ----------
        [TestCase("ip=<IPV4>", "ip=10.0.0.1", true)]
        [TestCase("ip=<IPV4>", "ip=256.0.0.1", false)] // invalid octet
        public void IPV4_Macro_ValidatesOctets(string pattern, string text, bool shouldMatch)
        {
            var re = IPBanRegexParser.ParseRegex(pattern);
            ClassicAssert.NotNull(re);
            ClassicAssert.AreEqual(shouldMatch, re.IsMatch(text));
            if (shouldMatch)
            {
                var m = re.Match(text);
                AssertGroup(m, "ipaddress", "10.0.0.1");
            }
        }

        // ---------- <IPV6> ----------
        [TestCase("ip=<IPV6>", "ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
        [TestCase("ip=<IPV6>", "ip=2001:db8::7334")]
        [TestCase("ip=<IPV6>", "ip=fe80::1%eth0")]
        public void IPV6_Macro_CoversForms(string pattern, string text)
        {
            var m = MatchSingle(pattern, text);
            StringAssert.Contains("ip=", text);
            var pi = text.IndexOf('%');
            if (pi < 0) pi = text.Length;
            StringAssert.AreEqualIgnoringCase(text[3..pi], m.Groups["ipaddress"].Value);
        }

        // ---------- <FQDN> ----------
        [TestCase("host=<FQDN>", "host=example.com", "example.com")]
        [TestCase("host=<FQDN>", "host=a.b-c123.xn--p1ai", "a.b-c123.xn--p1ai")]
        public void FQDN_Macro_MatchesValidDomains(string pattern, string text, string expected)
        {
            var m = MatchSingle(pattern, text);
            AssertGroup(m, "fqdn", expected);
        }

        [TestCase("host=<FQDN>", "host=-bad.example.com")]
        [TestCase("host=<FQDN>", "host=bad-.example.com")]
        [TestCase("host=<FQDN>", "host=example")] // no dot
        public void FQDN_Macro_RejectsInvalidDomains(string pattern, string text)
        {
            var re = IPBanRegexParser.ParseRegex(pattern);
            ClassicAssert.NotNull(re);
            ClassicAssert.IsFalse(re.IsMatch(text));
        }

        // ---------- <USER> ----------
        [TestCase("user=<USER>", "user=alice", "alice")]
        [TestCase("user=<USER>", "user=jeff_smith-99", "jeff_smith-99")]
        [TestCase("user=<USER>", "user=\"bob\"", "bob")] // quotes excluded by pattern
        public void USER_Macro_CapturesUsername(string pattern, string text, string expected)
        {
            var m = MatchSingle(pattern, text);
            AssertGroup(m, "username", expected);
        }

        // ---------- Python named groups and backrefs ----------
        [Test]
        public void Python_NamedGroup_IsConverted()
        {
            var m = MatchSingle(@"(?P<who>[a-z]+) said hi from <IP>", "alice said hi from 1.2.3.4");
            AssertGroup(m, "who", "alice");
            AssertGroup(m, "ipaddress", "1.2.3.4");
        }

        [Test]
        public void Python_NamedBackref_IsConverted()
        {
            var m = MatchSingle(@"(?P<who>[a-z]+) (?P=who) from <IP>", "bob bob from 5.6.7.8");
            AssertGroup(m, "who", "bob");
            AssertGroup(m, "ipaddress", "5.6.7.8");
        }

        // ---------- Inline flags normalization ----------
        [TestCase(@"(?i)failed from <IP>", "FAILED from 1.2.3.4")]
        [TestCase(@"(?imx)failed  \n  from\s<IP>", "FaIlEd\nfrom 1.2.3.4")]
        [TestCase(@"(?Liu)failed\sfrom\s<IP>", "failed from 1.2.3.4")] // L/u dropped; i kept
        public void InlineFlags_KeptOrDroppedAsExpected(string pattern, string text)
        {
            var re = IPBanRegexParser.ParseRegex(pattern, multiline: true);
            ClassicAssert.NotNull(re);
            ClassicAssert.IsTrue(re.IsMatch(text));
        }

        // ---------- Multiline prefix + capture combo ----------
        [Test]
        public void Multiline_WithPrefix_AndHost()
        {
            var pattern = "%(__prefix_line)sAuth failure for <USER> from <HOST>";
            var text = string.Join("\n", new[]
            {
                "Jan 11 10:00:01 x sshd[123]: Auth failure for bob from 10.0.0.9",
                "irrelevant line",
                "Jan 11 10:00:02 x sshd[123]: Auth failure for alice from 2001:db8::1"
            });

            var re = IPBanRegexParser.ParseRegex(pattern, multiline: true);
            ClassicAssert.NotNull(re);

            var matches = re.Matches(text).Cast<Match>().ToArray();
            ClassicAssert.AreEqual(2, matches.Length);

            AssertGroup(matches[0], "username", "bob");
            AssertGroup(matches[0], "ipaddress", "10.0.0.9");

            AssertGroup(matches[1], "username", "alice");
            AssertGroup(matches[1], "ipaddress", "2001:db8::1");
        }

        // ---------- $$file(fileOrUrl) syntax ----------
        [Test]
        public void FileReplacement_LocalFile_LiteralsEscaped_AndMatched()
        {
            // create a temporary file with a variety of literal lines
            var path = System.IO.Path.GetTempFileName();
            try
            {
                var lines = new[] { "abc", "def", "g.h", "x+y*z", " [brackets] " };
                System.IO.File.WriteAllLines(path, lines);

                // anchor so the entire input must match a line from the file
                var pattern = $"^$$file({path})$";
                var re = IPBanRegexParser.ParseRegex(pattern);
                ClassicAssert.NotNull(re);

                // positives
                ClassicAssert.IsTrue(re.IsMatch("abc"));
                ClassicAssert.IsTrue(re.IsMatch("def"));
                ClassicAssert.IsTrue(re.IsMatch("g.h"));
                ClassicAssert.IsTrue(re.IsMatch("x+y*z"));
                ClassicAssert.IsTrue(re.IsMatch("[brackets]")); // trimmed in replacement

                // negatives
                ClassicAssert.IsFalse(re.IsMatch("abcd"));
                ClassicAssert.IsFalse(re.IsMatch("gxh"));
                ClassicAssert.IsFalse(re.IsMatch("there"));
            }
            finally
            {
                try { System.IO.File.Delete(path); } catch { }
            }
        }

        [Test]
        public void FileReplacement_Url_ExpandsAndMatchesKnownWords()
        {
            // external test file contains four lines: testline, testline2, hello, there
            var url = "https://api.ipban.com/test.txt";
            var pattern = $"^$$file({url})$";
            var re = IPBanRegexParser.ParseRegex(pattern);
            ClassicAssert.NotNull(re);

            // if the remote file is not reachable, make the test inconclusive instead of failing the suite
            var anyMatch = re.IsMatch("testline") || re.IsMatch("testline2") || re.IsMatch("hello") || re.IsMatch("there");
            if (!anyMatch)
            {
                Assert.Inconclusive("Remote test list not reachable or contents changed.");
            }

            // when reachable, verify all expected tokens match and some negatives do not
            if (anyMatch)
            {
                ClassicAssert.IsTrue(re.IsMatch("testline"));
                ClassicAssert.IsTrue(re.IsMatch("testline2"));
                ClassicAssert.IsTrue(re.IsMatch("hello"));
                ClassicAssert.IsTrue(re.IsMatch("there"));

                ClassicAssert.IsFalse(re.IsMatch("unknown"));
                ClassicAssert.IsFalse(re.IsMatch("hello there")); // whole string must equal one list entry
            }
        }
    }
}
