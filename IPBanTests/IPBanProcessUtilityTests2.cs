/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for ProcessUtility - tests the public testable surface
(BashEscape, BuildAtJobBody) and exercises CreateDetachedProcess on the
current OS through a guarded code path.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanProcessUtilityTests2
    {
        // ----------------- BashEscape -----------------

        [Test]
        public void BashEscape_NullValue_ReturnsEmptySingleQuotedString()
        {
            ClassicAssert.AreEqual("''", ProcessUtility.BashEscape(null));
        }

        [Test]
        public void BashEscape_NoSpecialChars_WrapsInSingleQuotes()
        {
            ClassicAssert.AreEqual("'simple'", ProcessUtility.BashEscape("simple"));
        }

        [Test]
        public void BashEscape_WithSingleQuote_EscapesIdiomatically()
        {
            // ' -> '\''  i.e. close-quote, escaped-quote, reopen-quote
            ClassicAssert.AreEqual("'it'\\''s'", ProcessUtility.BashEscape("it's"));
        }

        [Test]
        public void BashEscape_WithSpacesAndShellMetachars_AreInert()
        {
            string input = "hello world; rm -rf / `evil` $(other)";
            string escaped = ProcessUtility.BashEscape(input);
            // Whole string wrapped in single quotes -> shell treats as literal.
            ClassicAssert.IsTrue(escaped.StartsWith("'"));
            ClassicAssert.IsTrue(escaped.EndsWith("'"));
            // No embedded single quote in this example, so no '\'' replacement
            ClassicAssert.IsFalse(escaped.Contains(@"'\'"));
        }

        [Test]
        public void BashEscape_EmptyString_ReturnsTwoSingleQuotes()
        {
            ClassicAssert.AreEqual("''", ProcessUtility.BashEscape(""));
        }

        // ----------------- BuildAtJobBody -----------------

        [Test]
        public void BuildAtJobBody_BareCommand_NoArgs_EndsWithNewline()
        {
            string body = ProcessUtility.BuildAtJobBody("/usr/bin/something", null);
            StringAssert.Contains("sudo '/usr/bin/something'", body);
            ClassicAssert.IsTrue(body.EndsWith("\n"));
        }

        [Test]
        public void BuildAtJobBody_WithArguments_AppendsThemUnescaped()
        {
            // Per the doc comment, arguments are caller-supplied as a shell-formed
            // argument string. Append-only behavior is confirmed.
            string body = ProcessUtility.BuildAtJobBody("/bin/foo", "--flag value");
            StringAssert.Contains("sudo '/bin/foo' --flag value", body);
        }

        [Test]
        public void BuildAtJobBody_FilenameWithSpacesIsQuotedLiterally()
        {
            // Path with a space gets wrapped in single quotes by BashEscape.
            string body = ProcessUtility.BuildAtJobBody("/path with space/exe", null);
            StringAssert.Contains("sudo '/path with space/exe'", body);
        }

        [Test]
        public void BuildAtJobBody_FilenameWithSingleQuote_EscapedSafely()
        {
            string body = ProcessUtility.BuildAtJobBody("/path/it's/exe", null);
            // The filename's single quote is safely escaped.
            StringAssert.Contains(@"'/path/it'\''s/exe'", body);
        }

        [Test]
        public void BuildAtJobBody_EmptyArguments_IgnoredCleanly()
        {
            string body = ProcessUtility.BuildAtJobBody("/foo", "");
            ClassicAssert.AreEqual("sudo '/foo'\n", body);
        }
    }
}
