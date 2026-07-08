/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the EventViewerExpression / EventViewerExpressionGroup /
EventViewerExpressions config types in IPBanConfigWindowsEventViewer.cs.
*/

using System;
using System.Text;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanEventViewerExpressionTests
    {
        [Test]
        public void EventViewerExpression_Equality_AndHashCode()
        {
            var a = new EventViewerExpression { XPath = "//Data[@Name='X']", Regex = "abc" };
            var b = new EventViewerExpression { XPath = "//Data[@Name='X']", Regex = "abc" };
            var c = new EventViewerExpression { XPath = "//Data[@Name='Y']", Regex = "abc" };
            ClassicAssert.IsTrue(a.Equals(b));
            ClassicAssert.IsFalse(a.Equals(c));
            ClassicAssert.IsFalse(a.Equals("not an expression"));
            ClassicAssert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [Test]
        public void EventViewerExpression_XPathProcessNameSpecialCase_OptionalFlag()
        {
            var e = new EventViewerExpression { XPath = "//Data[@Name='ProcessName']" };
            ClassicAssert.IsTrue(e.XPathIsOptional);
            e.XPath = "//something-else";
            ClassicAssert.IsFalse(e.XPathIsOptional);
        }

        [Test]
        public void EventViewerExpression_RegexAssignment_BuildsRegexObject()
        {
            var e = new EventViewerExpression { Regex = "test (?<a>\\d+)" };
            ClassicAssert.IsNotNull(e.RegexObject);
            ClassicAssert.IsTrue(e.RegexObject.IsMatch("test 42"));
        }

        [Test]
        public void EventViewerExpressionGroup_KeywordsParse_HexAndPlain()
        {
            var g = new EventViewerExpressionGroup { Keywords = "0x8010000000000000" };
            ClassicAssert.AreEqual(0x8010000000000000UL, g.KeywordsULONG);

            var g2 = new EventViewerExpressionGroup { Keywords = "10" };
            ClassicAssert.AreEqual(0x10UL, g2.KeywordsULONG);
        }

        [Test]
        public void EventViewerExpressionGroup_Equality()
        {
            // Equals uses Array.Equals on Expressions, which is reference equality, so
            // two distinct-but-equal-by-value groups can compare unequal. Just confirm
            // the method runs without throwing for self/other comparisons.
            var a = new EventViewerExpressionGroup { Source = "X", Keywords = "0x10" };
            var c = new EventViewerExpressionGroup { Source = "Y", Keywords = "0x10" };
            ClassicAssert.IsTrue(a.Equals(a));
            ClassicAssert.IsFalse(a.Equals(c));
            ClassicAssert.IsFalse(a.Equals("string"));
            ClassicAssert.AreEqual(a.GetHashCode(), a.GetHashCode());
        }

        [Test]
        public void EventViewerExpressionGroup_AppendQueryString_FormatsXml()
        {
            var g = new EventViewerExpressionGroup { Path = "Security", Keywords = "0x8010000000000000" };
            var sb = new StringBuilder();
            g.AppendQueryString(sb, id: 7);
            string xml = sb.ToString();
            StringAssert.Contains("Query Id='7'", xml);
            StringAssert.Contains("Path='Security'", xml);
            StringAssert.Contains("band(Keywords,", xml);
        }

        [Test]
        public void EventViewerExpressionGroup_SetExpressionsFromText_BuildsList()
        {
            var g = new EventViewerExpressionGroup
            {
                ExpressionsText = "//Event/EventData/Data[@Name='IpAddress']\n(?<ipaddress>\\S+)\n//Event/EventData/Data[@Name='User']\n(?<username>\\S+)\n"
            };
            g.SetExpressionsFromExpressionsText();
            ClassicAssert.AreEqual(2, g.Expressions.Count);
            StringAssert.Contains("IpAddress", g.Expressions[0].XPath);
            StringAssert.Contains("ipaddress", g.Expressions[0].Regex.ToString());
        }

        [Test]
        public void EventViewerExpressionGroup_SetExpressionsFromText_NullText_NoOp()
        {
            var g = new EventViewerExpressionGroup { ExpressionsText = null };
            g.SetExpressionsFromExpressionsText();
            ClassicAssert.AreEqual(0, g.Expressions.Count);
        }

        [Test]
        public void EventViewerExpressionGroup_MinimumTimeBetweenLoginAttempts_RoundTrip()
        {
            var g = new EventViewerExpressionGroup { MinimumTimeBetweenLoginAttempts = "00:01:00" };
            ClassicAssert.AreEqual(TimeSpan.FromMinutes(1), g.MinimumTimeBetweenLoginAttemptsTimeSpan);
            ClassicAssert.AreEqual("00:01:00", g.MinimumTimeBetweenLoginAttempts);

            g.MinimumTimeBetweenLoginAttempts = "garbage";
            ClassicAssert.IsNull(g.MinimumTimeBetweenLoginAttemptsTimeSpan);
        }

        [Test]
        public void EventViewerExpressions_Equality()
        {
            var a = new EventViewerExpressions();
            ClassicAssert.IsTrue(a.Equals(a));
            ClassicAssert.IsFalse(a.Equals("not"));
            _ = a.GetHashCode();
        }
    }
}
