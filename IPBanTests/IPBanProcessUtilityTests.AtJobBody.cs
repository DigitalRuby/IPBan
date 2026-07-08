/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for ProcessUtility.BuildAtJobBody — the helper that assembles the shell
script body piped into the Linux `at` daemon by CreateDetachedProcess.
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    public partial class IPBanProcessUtilityTests
    {
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
