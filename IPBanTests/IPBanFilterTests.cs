using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    /// <summary>
    /// IPBan filter tests
    /// </summary>
    [TestFixture]
    public sealed class IPBanFilterTests
    {
        /// <summary>
        /// Ensure we can get entry without comment using old and new delimiter properly
        /// </summary>
        [TestCase("1.2.3.4?2022-01-01T01:01:01Z?notes", "1.2.3.4")]
        [TestCase("1.2.3.4|2022-01-01T01:01:01Z|notes", "1.2.3.4")]
        [TestCase("https://fakeurl.com/?t=123", "https://fakeurl.com/?t=123")]
        [TestCase("https://fakeurl.com/?t=123|2022-01-01T01:01:01Z|notes", "https://fakeurl.com/?t=123")]
        public void TestGetEntryWithoutComment(string entry, string expectedResult)
        {
            string result = IPBanFilter.GetEntryWithoutComment(entry);
            Assert.That(result, Is.EqualTo(expectedResult));
        }

        /// <summary>
        /// Ensure we can split using old and new delimiters properly
        /// </summary>
        /// <param name="entry">Entry</param>
        /// <param name="expectedResult">Expected result (3 items, | separated)</param>
        [TestCase("1.2.3.4?2022-01-01T01:01:01Z?notes", "1.2.3.4|2022-01-01T01:01:01Z|notes")]
        [TestCase("1.2.3.4|2022-01-01T01:01:01Z|notes", "1.2.3.4|2022-01-01T01:01:01Z|notes")]
        [TestCase("https://fakeurl.com/?t=123", "https://fakeurl.com/?t=123||")]
        [TestCase("https://fakeurl.com/?t=123|2022-01-01T01:01:01Z|notes", "https://fakeurl.com/?t=123|2022-01-01T01:01:01Z|notes")]
        public void TestSplitEntry(string entry, string expectedResult)
        {
            string[] result = IPBanFilter.SplitEntry(entry);
            Assert.That(string.Join('|', result), Is.EqualTo(expectedResult));
        }
    }
}
