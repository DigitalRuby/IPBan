/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for LevenshteinUnsafe (C4 — bounded stackalloc to prevent uncatchable
StackOverflowException on attacker-controlled input).
*/

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// LevenshteinUnsafe.Distance correctness and bounds.
    /// </summary>
    [TestFixture]
    public sealed class IPBanLevenshteinUnsafeTests
    {
        [Test]
        public void NullInputsReturnMinusOne()
        {
            ClassicAssert.AreEqual(-1, LevenshteinUnsafe.Distance(null, "a"));
            ClassicAssert.AreEqual(-1, LevenshteinUnsafe.Distance("a", null));
            ClassicAssert.AreEqual(-1, LevenshteinUnsafe.Distance(null, null));
        }

        [Test]
        public void EmptyInputsReturnOtherLength()
        {
            ClassicAssert.AreEqual(0, LevenshteinUnsafe.Distance("", ""));
            ClassicAssert.AreEqual(3, LevenshteinUnsafe.Distance("abc", ""));
            ClassicAssert.AreEqual(3, LevenshteinUnsafe.Distance("", "abc"));
        }

        [TestCase("kitten", "sitting", 3)]
        [TestCase("flaw", "lawn", 2)]
        [TestCase("intention", "execution", 5)]
        [TestCase("abc", "abc", 0)]
        [TestCase("a", "b", 1)]
        public void KnownDistances(string a, string b, int expected)
        {
            ClassicAssert.AreEqual(expected, LevenshteinUnsafe.Distance(a, b));
        }

        [Test]
        public void OverMaxLengthReturnsMinusTwo()
        {
            // C4 regression — hostile input must be rejected, not crash via StackOverflowException.
            string huge1 = new string('x', LevenshteinUnsafe.MaxInputLength + 1);
            string huge2 = new string('y', LevenshteinUnsafe.MaxInputLength + 1);
            ClassicAssert.AreEqual(-2, LevenshteinUnsafe.Distance(huge1, "ok"));
            ClassicAssert.AreEqual(-2, LevenshteinUnsafe.Distance("ok", huge2));
            ClassicAssert.AreEqual(-2, LevenshteinUnsafe.Distance(huge1, huge2));
        }

        [Test]
        public void AtMaxLengthIsAccepted()
        {
            // boundary — exactly MaxInputLength is allowed
            string max = new string('a', LevenshteinUnsafe.MaxInputLength);
            ClassicAssert.AreEqual(0, LevenshteinUnsafe.Distance(max, max));
        }

        [Test]
        public void HeapPathProducesSameAnswerAsStackPath()
        {
            // ensure the threshold-based stack/heap branch is consistent — when value2.Length crosses
            // the internal StackAllocThreshold we go to the heap; both paths must compute the same distance.
            string a = new string('a', 600);                       // 600 chars
            string b = new string('a', 600).Insert(0, "x");        // 601 chars, distance 1 (one extra 'x' prefix)
            // value2.Length is 601 > StackAllocThreshold (256) → heap path is exercised
            ClassicAssert.AreEqual(1, LevenshteinUnsafe.Distance(a, b));
        }
    }
}
