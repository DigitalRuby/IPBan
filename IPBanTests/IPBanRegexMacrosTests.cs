/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for IPBanRegexMacros.Expand — the function that translates fail2ban-style
regex syntax (Python `(?P<name>…)` named groups, `<HOST>` / `<IP>` / `<USER>`
macros, inline flags) into something the .NET Regex engine can compile. A bug
here silently corrupts every fail2ban-style filter the user imports, so we want
to make sure each substitution and the final regex compilation are exercised.
*/

using System.Text.RegularExpressions;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanRegexMacrosTests
    {
        // -------------------- empty / trivial inputs --------------------

        [Test]
        public void Expand_NullReturnsEmpty()
        {
            ClassicAssert.AreEqual(string.Empty, IPBanRegexMacros.Expand(null));
        }

        [Test]
        public void Expand_EmptyReturnsEmpty()
        {
            ClassicAssert.AreEqual(string.Empty, IPBanRegexMacros.Expand(string.Empty));
        }

        [Test]
        public void Expand_WhitespaceOnlyIsLeftAlone()
        {
            // The function returns the input pattern when blank, not "" — but null/empty
            // both come back as "". Match that contract precisely.
            ClassicAssert.AreEqual("   ", IPBanRegexMacros.Expand("   "));
        }

        [Test]
        public void Expand_UnchangedWhenNoMacros()
        {
            // A regex with no macros / no Python syntax should round-trip byte-for-byte.
            const string input = @"^Failed login from (\d+\.\d+\.\d+\.\d+) for user \w+$";
            ClassicAssert.AreEqual(input, IPBanRegexMacros.Expand(input));
        }

        // -------------------- macro substitution --------------------

        [Test]
        public void Expand_HOST_BecomesNamedIpAddressGroup()
        {
            string expanded = IPBanRegexMacros.Expand("login from <HOST>");
            // The expanded regex must contain a named group called 'ipaddress'
            StringAssert.Contains("(?<ipaddress>", expanded);
            // And the macro literal must be gone
            StringAssert.DoesNotContain("<HOST>", expanded);

            // The result must be a compilable .NET regex
            Assert.DoesNotThrow(() => new Regex(expanded));
        }

        [Test]
        public void Expand_HOST_MatchesIPv4_IPv6_AndFqdn()
        {
            // The HOST macro is documented to match both IP addresses and FQDNs. Build a
            // real regex and try a few known-good inputs against it.
            string expanded = "^login from " + IPBanRegexMacros.Expand("<HOST>") + "$";
            var re = new Regex(expanded);

            ClassicAssert.IsTrue(re.IsMatch("login from 1.2.3.4"));
            ClassicAssert.IsTrue(re.IsMatch("login from 192.168.0.1"));
            ClassicAssert.IsTrue(re.IsMatch("login from ::1"));
            ClassicAssert.IsTrue(re.IsMatch("login from fe80::c872:be03:5c94:4af2"));
            ClassicAssert.IsTrue(re.IsMatch("login from foo.example.com"));
        }

        [Test]
        public void Expand_IP_DoesNotMatchFqdn()
        {
            // <IP> is an IPv4-or-IPv6 only macro — it must NOT match a hostname.
            string expanded = "^from " + IPBanRegexMacros.Expand("<IP>") + "$";
            var re = new Regex(expanded);

            ClassicAssert.IsTrue(re.IsMatch("from 10.20.30.40"));
            ClassicAssert.IsTrue(re.IsMatch("from 2001:db8::1"));
            ClassicAssert.IsFalse(re.IsMatch("from foo.example.com"),
                "<IP> macro should reject FQDNs — that's what <HOST> is for");
        }

        [Test]
        public void Expand_IPV4_RejectsIPv6()
        {
            string expanded = "^from " + IPBanRegexMacros.Expand("<IPV4>") + "$";
            var re = new Regex(expanded);

            ClassicAssert.IsTrue(re.IsMatch("from 192.168.1.1"));
            ClassicAssert.IsFalse(re.IsMatch("from 2001:db8::1"),
                "<IPV4> macro should reject v6 addresses");
        }

        [Test]
        public void Expand_USER_CapturesQuotedAndUnquotedNames()
        {
            // The <USER> macro yields a (?<username>…) group that allows optional quoting.
            string expanded = "^login " + IPBanRegexMacros.Expand("<USER>") + "$";
            var re = new Regex(expanded);

            var m1 = re.Match("login alice");
            ClassicAssert.IsTrue(m1.Success);
            ClassicAssert.AreEqual("alice", m1.Groups["username"].Value);

            var m2 = re.Match("login \"alice\"");
            ClassicAssert.IsTrue(m2.Success);
            ClassicAssert.AreEqual("alice", m2.Groups["username"].Value);

            var m3 = re.Match("login 'bob'");
            ClassicAssert.IsTrue(m3.Success);
            ClassicAssert.AreEqual("bob", m3.Groups["username"].Value);
        }

        [Test]
        public void Expand_FQDN_CapturesHostname()
        {
            string expanded = "^from " + IPBanRegexMacros.Expand("<FQDN>") + "$";
            var re = new Regex(expanded);

            var m = re.Match("from server01.example.org");
            ClassicAssert.IsTrue(m.Success);
            ClassicAssert.AreEqual("server01.example.org", m.Groups["fqdn"].Value);
        }

        [Test]
        public void Expand_PrefixLineMacro_BecomesLazyDotStar()
        {
            // fail2ban's __prefix_line is the daemon's syslog prefix — translated to ".*?"
            // so it greedy-eats whatever comes before the actual log content.
            string expanded = IPBanRegexMacros.Expand("%(__prefix_line)sFailed");
            ClassicAssert.AreEqual(".*?Failed", expanded);
        }

        [Test]
        public void Expand_MacrosAreCaseInsensitive()
        {
            // Macros are documented to ignore case (StringComparison.OrdinalIgnoreCase).
            // Both <host> and <HOST> should produce the same expansion.
            ClassicAssert.AreEqual(
                IPBanRegexMacros.Expand("<HOST>"),
                IPBanRegexMacros.Expand("<host>"));
            ClassicAssert.AreEqual(
                IPBanRegexMacros.Expand("<USER>"),
                IPBanRegexMacros.Expand("<UsEr>"));
        }

        // -------------------- Python regex syntax conversion --------------------

        [Test]
        public void Expand_PythonNamedGroup_BecomesDotNetNamedGroup()
        {
            // Python: (?P<name>...)   .NET: (?<name>...)
            // Group name is "account" rather than "user" because the macro substitution runs
            // BEFORE the Python translation and is case-insensitive — `<user>` would match the
            // <USER> macro and get rewritten before the (?P translation can fire.
            string expanded = IPBanRegexMacros.Expand(@"(?P<account>\w+) failed");
            StringAssert.Contains(@"(?<account>", expanded);
            StringAssert.DoesNotContain("(?P<", expanded);
            // And the result is a valid .NET regex
            Assert.DoesNotThrow(() => new Regex(expanded));
        }

        [Test]
        public void Expand_PythonNamedBackref_BecomesDotNetBackref()
        {
            // Python: (?P=name)   .NET: \k<name>
            string expanded = IPBanRegexMacros.Expand(@"(?P<n>\w+) and \1 also (?P=n)");
            StringAssert.Contains(@"\k<n>", expanded);
            StringAssert.DoesNotContain("(?P=", expanded);
            // The whole pattern compiles cleanly
            Assert.DoesNotThrow(() => new Regex(expanded));
        }

        [Test]
        public void Expand_PythonNamedGroupAndBackref_RoundTrip()
        {
            // End-to-end: both opening syntax and back-reference syntax in the same pattern.
            string expanded = IPBanRegexMacros.Expand(@"(?P<word>\w+)\s+(?P=word)");
            var re = new Regex(expanded);

            var m = re.Match("hello hello");
            ClassicAssert.IsTrue(m.Success, "back-reference must match the captured group");
            ClassicAssert.AreEqual("hello", m.Groups["word"].Value);

            ClassicAssert.IsFalse(re.IsMatch("hello world"),
                "back-reference must not match a different word");
        }

        // -------------------- inline flags --------------------

        [Test]
        public void Expand_InlineFlags_KeepsSupportedAndDropsRest()
        {
            // .NET supports imnsx; Python's L (locale) and u (unicode) are dropped.
            // Expanded "(?Liu)" should reduce to "(?i)" — i is supported, L and u are not.
            string expanded = IPBanRegexMacros.Expand("(?Liu)pattern");
            StringAssert.Contains("(?i)", expanded);
            StringAssert.DoesNotContain("L", expanded.Replace("Liu", ""));
            // result compiles
            Assert.DoesNotThrow(() => new Regex(expanded));
        }

        [Test]
        public void Expand_InlineFlags_AllUnsupportedDropsTheGroupEntirely()
        {
            // If every flag in the group is unsupported, the entire (?...) marker should
            // disappear rather than leave behind an empty group like "(?)".
            string expanded = IPBanRegexMacros.Expand("(?Lu)pattern");
            StringAssert.DoesNotContain("(?", expanded);
            StringAssert.DoesNotContain("(?L", expanded);
            ClassicAssert.AreEqual("pattern", expanded);
        }

        [Test]
        public void Expand_InlineFlags_SupportsAllDotNetFlags()
        {
            // imnsx are all .NET-supported — they should round-trip unchanged.
            string expanded = IPBanRegexMacros.Expand("(?imnsx)abc");
            StringAssert.Contains("(?imnsx)", expanded);
            Assert.DoesNotThrow(() => new Regex(expanded));
        }

        // -------------------- realistic combined patterns --------------------

        [Test]
        public void Expand_RealisticFail2BanSshdPattern_Compiles()
        {
            // Lifted from a typical fail2ban filter.d/sshd.conf —
            // Python named group, HOST macro, prefix_line, inline flag.
            // Group name is "account" instead of "user" so it doesn't collide with the
            // case-insensitive <USER> macro substitution that runs first.
            string fail2ban = @"(?Lu)%(__prefix_line)sFailed password for (?P<account>.+) from <HOST>";
            string expanded = IPBanRegexMacros.Expand(fail2ban);

            // Each translation step is visible in the output
            StringAssert.Contains(".*?", expanded);                 // %(__prefix_line)s
            StringAssert.Contains("(?<account>", expanded);         // (?P<account>
            StringAssert.Contains("(?<ipaddress>", expanded);       // <HOST>
            StringAssert.DoesNotContain("(?P<", expanded);
            StringAssert.DoesNotContain("<HOST>", expanded);
            StringAssert.DoesNotContain("(?L", expanded);           // unsupported flag dropped

            // And it compiles into a usable .NET regex
            var re = new Regex(expanded);
            var m = re.Match("Jul 12 10:11:12 host sshd[1234]: Failed password for alice from 10.20.30.40");
            ClassicAssert.IsTrue(m.Success, "compiled regex should match a representative sshd log line");
            ClassicAssert.AreEqual("alice", m.Groups["account"].Value);
            ClassicAssert.AreEqual("10.20.30.40", m.Groups["ipaddress"].Value);
        }
    }
}
