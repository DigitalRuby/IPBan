/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for BinaryExtensionMethods. Forces resolution to our extension
methods (rather than the BCL built-ins on .NET 5+) by calling them via the
static class.
*/

using System;
using System.IO;
using System.Text;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanBinaryExtensionMethodsExplicitTests
    {
        [TestCase(0L)]
        [TestCase(1L)]
        [TestCase(0x7FL)]
        [TestCase(0x80L)]
        [TestCase((long)int.MaxValue + 1)]
        [TestCase(long.MaxValue)]
        [TestCase(-1L)]
        [TestCase(long.MinValue)]
        public void Int64_ExplicitExtensionMethod_RoundTrip(long value)
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                BinaryExtensionMethods.Write7BitEncodedInt64(w, value);
            }
            ms.Position = 0;
            using var r = new BinaryReader(ms);
            ClassicAssert.AreEqual(value, BinaryExtensionMethods.Read7BitEncodedInt64(r));
        }

        [Test]
        public void Int64_Extension_CorruptedStreamThrowsFormatException()
        {
            byte[] corrupt = new byte[12];
            for (int i = 0; i < corrupt.Length; i++) corrupt[i] = 0x80;
            using var ms = new MemoryStream(corrupt);
            using var r = new BinaryReader(ms);
            Assert.Throws<FormatException>(() => BinaryExtensionMethods.Read7BitEncodedInt64(r));
        }

        [TestCase(0)]
        [TestCase(1)]
        [TestCase(0x7F)]
        [TestCase(int.MaxValue)]
        [TestCase(-1)]
        [TestCase(int.MinValue)]
        public void Int32_ExplicitExtensionMethod_RoundTrip(int value)
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                BinaryExtensionMethods.Write7BitEncodedInt32(w, value);
            }
            ms.Position = 0;
            using var r = new BinaryReader(ms);
            ClassicAssert.AreEqual(value, BinaryExtensionMethods.Read7BitEncodedInt32(r));
        }
    }
}
