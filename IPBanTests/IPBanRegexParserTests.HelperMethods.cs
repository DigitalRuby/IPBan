/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for IPBanRegexParser - CleanMultilineString, ValidateRegex,
GetIPAddressEventsFromRegex, TruncateUserNameChars, and the $$file substitution
path. Complements the macro-focused IPBanRegexParserTests.cs.
*/

using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    public sealed partial class IPBanRegexParserTests
    {
        [Test]
        public void TruncateUserNameChars_RoundTrips()
        {
            string prev = IPBanRegexParser.TruncateUserNameChars;
            try
            {
                IPBanRegexParser.TruncateUserNameChars = "@\\";
                ClassicAssert.AreEqual("@\\", IPBanRegexParser.TruncateUserNameChars);
                IPBanRegexParser.TruncateUserNameChars = null;
                ClassicAssert.AreEqual(string.Empty, IPBanRegexParser.TruncateUserNameChars);
            }
            finally
            {
                IPBanRegexParser.TruncateUserNameChars = prev;
            }
        }

        [Test]
        public void ParseRegex_NullOrWhitespace_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanRegexParser.ParseRegex(null));
            ClassicAssert.IsNull(IPBanRegexParser.ParseRegex(""));
            ClassicAssert.IsNull(IPBanRegexParser.ParseRegex("   "));
        }

        [Test]
        public void ParseRegex_BasicPattern_CompilesAndCaches()
        {
            var r = IPBanRegexParser.ParseRegex("ip=(?<ipaddress>\\S+)");
            ClassicAssert.IsNotNull(r);
            // Calling again with the same text returns the cached instance.
            var r2 = IPBanRegexParser.ParseRegex("ip=(?<ipaddress>\\S+)");
            ClassicAssert.AreSame(r, r2);
        }

        [Test]
        public void ParseRegex_MultilinePattern_UsesMultilineFlag()
        {
            var r = IPBanRegexParser.ParseRegex("foo", multiline: true);
            ClassicAssert.IsNotNull(r);
            ClassicAssert.IsTrue(r.Options.HasFlag(RegexOptions.Multiline));
        }

        [Test]
        public void ParseRegex_FileSubstitution_BuildsAlternation()
        {
            string filePath = Path.Combine(Path.GetTempPath(), "ipban_regex_filesub_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllLines(filePath, new[] { "alpha", "beta", "gamma" });
                var r = IPBanRegexParser.ParseRegex($"user=$$file({filePath})");
                ClassicAssert.IsNotNull(r);
                ClassicAssert.IsTrue(r.IsMatch("user=alpha"));
                ClassicAssert.IsTrue(r.IsMatch("user=beta"));
                ClassicAssert.IsFalse(r.IsMatch("user=delta"));
            }
            finally
            {
                try { File.Delete(filePath); } catch { /* best effort */ }
            }
        }

        [Test]
        public void ParseRegex_FileSubstitution_MissingFile_DoesNotThrow()
        {
            string missing = Path.Combine(Path.GetTempPath(), "definitely-not-here-" + Guid.NewGuid().ToString("N") + ".txt");
            var r = IPBanRegexParser.ParseRegex($"user=$$file({missing})");
            ClassicAssert.IsNotNull(r);
        }

        [Test]
        public void CleanMultilineString_HandlesNullEmptyAndCData()
        {
            ClassicAssert.AreEqual(string.Empty, IPBanRegexParser.CleanMultilineString(null));
            ClassicAssert.AreEqual(string.Empty, IPBanRegexParser.CleanMultilineString(""));
            ClassicAssert.AreEqual(string.Empty, IPBanRegexParser.CleanMultilineString("   "));

            string input = "\n  line1\n\n  line2  \n line3  ";
            string cleaned = IPBanRegexParser.CleanMultilineString(input);
            StringAssert.Contains("line1", cleaned);
            StringAssert.Contains("line2", cleaned);
            StringAssert.Contains("line3", cleaned);
            ClassicAssert.AreEqual(cleaned, cleaned.Trim());

            // CDATA wrap is stripped
            string cdata = "<![CDATA[\n  inner  \n]]>";
            string cleanedCdata = IPBanRegexParser.CleanMultilineString(cdata);
            StringAssert.Contains("inner", cleanedCdata);
            ClassicAssert.IsFalse(cleanedCdata.Contains("CDATA"));
        }

        [Test]
        public void ValidateRegex_GoodPattern_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanRegexParser.ValidateRegex(@"\d+"));
        }

        [Test]
        public void ValidateRegex_NullPattern_ReturnsNull()
        {
            ClassicAssert.IsNull(IPBanRegexParser.ValidateRegex(null));
        }

        [Test]
        public void ValidateRegex_BadPattern_ReturnsErrorMessage()
        {
            string msg = IPBanRegexParser.ValidateRegex(@"(unclosed");
            ClassicAssert.IsNotNull(msg);
            ClassicAssert.IsNotEmpty(msg);
        }

        [Test]
        public void ValidateRegex_BadPattern_ThrowsWhenAsked()
        {
            Assert.Throws<RegexParseException>(() => IPBanRegexParser.ValidateRegex(@"(unclosed", throwException: true));
        }

        [Test]
        public void GetIPAddressEventsFromRegex_NullOrEmpty_YieldsNothing()
        {
            CollectionAssert.IsEmpty(IPBanRegexParser.GetIPAddressEventsFromRegex(null, "text").ToArray());
            var r = new Regex("test");
            CollectionAssert.IsEmpty(IPBanRegexParser.GetIPAddressEventsFromRegex(r, null).ToArray());
            CollectionAssert.IsEmpty(IPBanRegexParser.GetIPAddressEventsFromRegex(r, string.Empty).ToArray());
        }

        [Test]
        public void GetIPAddressEventsFromRegex_BasicMatch_YieldsEvent()
        {
            var r = IPBanRegexParser.ParseRegex(@"Failed password for (?<username>\S+) from (?<ipaddress>\S+)");
            var events = IPBanRegexParser.GetIPAddressEventsFromRegex(r,
                "Failed password for alice from 1.2.3.4").ToArray();
            ClassicAssert.AreEqual(1, events.Length);
            ClassicAssert.AreEqual("alice", events[0].UserName);
            ClassicAssert.AreEqual("1.2.3.4", events[0].IPAddress);
        }
    }
}
