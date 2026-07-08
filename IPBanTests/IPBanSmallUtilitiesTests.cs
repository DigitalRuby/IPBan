/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the small utility classes that previously had zero coverage:
ByteArrayKey, JsonGuidConverter, BinaryExtensionMethods, IPBanNullFirewall.
Each is small enough to fully cover in a single fixture so doing them as a
batch is efficient.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    // -------------------- ByteArrayKey --------------------

    [TestFixture]
    public sealed class IPBanByteArrayKeyTests
    {
        [Test]
        public void Construct_StoresBytes()
        {
            byte[] data = { 1, 2, 3, 4 };
            var key = new ByteArrayKey(data);
            CollectionAssert.AreEqual(data, key.Bytes);
        }

        [Test]
        public void EqualBytes_AreEqual()
        {
            var a = new ByteArrayKey(new byte[] { 1, 2, 3 });
            var b = new ByteArrayKey(new byte[] { 1, 2, 3 });

            ClassicAssert.IsTrue(a == b);
            ClassicAssert.IsFalse(a != b);
            ClassicAssert.IsTrue(a.Equals(b));
            ClassicAssert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [Test]
        public void DifferentBytes_AreNotEqual()
        {
            var a = new ByteArrayKey(new byte[] { 1, 2, 3 });
            var b = new ByteArrayKey(new byte[] { 1, 2, 4 });

            ClassicAssert.IsFalse(a == b);
            ClassicAssert.IsTrue(a != b);
            ClassicAssert.IsFalse(a.Equals(b));
        }

        [Test]
        public void DifferentLength_AreNotEqual()
        {
            var a = new ByteArrayKey(new byte[] { 1, 2, 3 });
            var b = new ByteArrayKey(new byte[] { 1, 2, 3, 4 });
            ClassicAssert.IsFalse(a.Equals(b));
        }

        [Test]
        public void HashCode_IsStableAcrossCalls()
        {
            var key = new ByteArrayKey(new byte[] { 1, 2, 3, 4 });
            ClassicAssert.AreEqual(key.GetHashCode(), key.GetHashCode());
        }

        [Test]
        public void Equals_WithNonKeyObject_ReturnsFalse()
        {
            var key = new ByteArrayKey(new byte[] { 1, 2, 3 });
            ClassicAssert.IsFalse(key.Equals("not a key"));
            ClassicAssert.IsFalse(key.Equals(null));
        }

        [Test]
        public void EmptyBytes_AreEqual()
        {
            var a = new ByteArrayKey(Array.Empty<byte>());
            var b = new ByteArrayKey(Array.Empty<byte>());
            ClassicAssert.IsTrue(a.Equals(b));
            ClassicAssert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }
    }

    // -------------------- JsonGuidConverter --------------------

    [TestFixture]
    public sealed class IPBanJsonGuidConverterTests
    {
        private static readonly JsonSerializerOptions options = new()
        {
            Converters = { new JsonGuidConverter() }
        };

        [Test]
        public void Write_ProducesBase64String_ShorterThanCanonicalGuidString()
        {
            // The point of JsonGuidConverter is compactness — the base64 form is shorter than
            // the canonical 36-char hyphenated GUID string.
            var guid = new Guid("12345678-1234-1234-1234-1234567890AB");
            string json = JsonSerializer.Serialize(guid, options);
            // strip surrounding quotes
            string body = json.Trim('"');
            ClassicAssert.IsTrue(body.Length < 36,
                $"base64 form should be shorter than 36; got {body.Length}: {body}");
        }

        [Test]
        public void Read_RoundTripsThroughBase64()
        {
            var guid = Guid.NewGuid();
            string json = JsonSerializer.Serialize(guid, options);
            Guid back = JsonSerializer.Deserialize<Guid>(json, options);
            ClassicAssert.AreEqual(guid, back);
        }

        [Test]
        public void Read_AcceptsCanonicalGuidStringFallback()
        {
            // The reader tries base64 first; if that fails, falls back to standard Guid.Parse.
            // This lets old data files that wrote canonical GUIDs still parse.
            var guid = Guid.NewGuid();
            string canonical = $"\"{guid}\"";
            Guid back = JsonSerializer.Deserialize<Guid>(canonical, options);
            ClassicAssert.AreEqual(guid, back);
        }

        [Test]
        public void Read_GarbageReturnsEmpty()
        {
            // Neither base64 nor canonical — falls through to Guid.Empty rather than throwing.
            Guid back = JsonSerializer.Deserialize<Guid>("\"not-a-guid\"", options);
            ClassicAssert.AreEqual(Guid.Empty, back);
        }

        [Test]
        public void Read_EmptyStringReturnsEmpty()
        {
            Guid back = JsonSerializer.Deserialize<Guid>("\"\"", options);
            ClassicAssert.AreEqual(Guid.Empty, back);
        }

        [Test]
        public void RoundTrip_KnownVectors()
        {
            // A handful of known guids round-trip cleanly.
            Guid[] vectors =
            {
                Guid.Empty,
                new Guid("00000000-0000-0000-0000-000000000001"),
                new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff"),
                Guid.NewGuid(),
                Guid.NewGuid(),
            };
            foreach (var g in vectors)
            {
                string json = JsonSerializer.Serialize(g, options);
                ClassicAssert.AreEqual(g, JsonSerializer.Deserialize<Guid>(json, options),
                    $"round-trip failed for {g}");
            }
        }
    }

    // -------------------- BinaryExtensionMethods (7-bit varint) --------------------

    [TestFixture]
    public sealed class IPBanBinaryExtensionMethodsTests
    {
        // -------- Int32 --------

        [TestCase(0)]
        [TestCase(1)]
        [TestCase(0x7F)]      // 1-byte boundary
        [TestCase(0x80)]      // 2-byte boundary
        [TestCase(0x3FFF)]
        [TestCase(0x4000)]
        [TestCase(int.MaxValue)]
        [TestCase(-1)]
        [TestCase(int.MinValue)]
        public void Int32_RoundTrip(int value)
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write7BitEncodedInt32(value);
            }
            ms.Position = 0;
            using var r = new BinaryReader(ms);
            ClassicAssert.AreEqual(value, r.Read7BitEncodedInt32());
        }

        [Test]
        public void Int32_SmallValueUses1Byte()
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write7BitEncodedInt32(42);
            }
            ClassicAssert.AreEqual(1, ms.Length, "values < 128 should fit in 1 byte");
        }

        [Test]
        public void Int32_NegativeUses5Bytes()
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write7BitEncodedInt32(-1);
            }
            ClassicAssert.AreEqual(5, ms.Length, "negative numbers (high bit set) span all 5 bytes");
        }

        [Test]
        public void Int32_CorruptedStreamThrowsFormatException()
        {
            // Write 6+ bytes with continuation bits set — the reader should throw before
            // shift goes past the 5 * 7 = 35 limit.
            byte[] corrupt = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
            using var ms = new MemoryStream(corrupt);
            using var r = new BinaryReader(ms);
            Assert.Throws<FormatException>(() => r.Read7BitEncodedInt32());
        }

        // -------- Int64 --------

        [TestCase(0L)]
        [TestCase(1L)]
        [TestCase(0x7FL)]
        [TestCase(0x80L)]
        [TestCase(int.MaxValue)]
        [TestCase((long)int.MaxValue + 1)]
        [TestCase(long.MaxValue)]
        [TestCase(-1L)]
        [TestCase(long.MinValue)]
        public void Int64_RoundTrip(long value)
        {
            using var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                w.Write7BitEncodedInt64(value);
            }
            ms.Position = 0;
            using var r = new BinaryReader(ms);
            ClassicAssert.AreEqual(value, r.Read7BitEncodedInt64());
        }

        [Test]
        public void Int64_CorruptedStreamThrowsFormatException()
        {
            // 11+ bytes with continuation bits — exceeds the 10-byte cap for Int64.
            byte[] corrupt = new byte[12];
            for (int i = 0; i < corrupt.Length; i++)
            {
                corrupt[i] = 0x80;
            }
            using var ms = new MemoryStream(corrupt);
            using var r = new BinaryReader(ms);
            Assert.Throws<FormatException>(() => r.Read7BitEncodedInt64());
        }
    }

    // -------------------- IPBanLogFileTester --------------------

    [TestFixture]
    public sealed class IPBanLogFileTesterTests
    {
        [Test]
        public void RunLogFileTest_ProcessesEachLine_WithoutCrashing()
        {
            // RunLogFileTest is a CLI helper used by `ipban logfiletest <file>`. It opens the
            // source file, copies each line into a sibling .temp file, runs the scanner once
            // per line, then deletes the temp. Verify the whole flow runs end-to-end without
            // throwing on a small synthetic log.
            string srcPath = Path.Combine(Path.GetTempPath(), "ipban_logtest_" + Guid.NewGuid().ToString("N") + ".log");
            File.WriteAllLines(srcPath, new[]
            {
                "2024-01-01 12:00:00 sshd[1234]: Failed password for alice from 1.2.3.4",
                "2024-01-01 12:00:01 sshd[1234]: Failed password for bob   from 5.6.7.8",
                "noise line that doesn't match",
            });

            try
            {
                Assert.DoesNotThrow(() => IPBanLogFileTester.RunLogFileTest(
                    fileName: srcPath,
                    regexFailure: @"Failed password for (?<username>\S+)\s+from (?<ipaddress>\S+)",
                    regexFailureTimestampFormat: "yyyy-MM-dd HH:mm:ss",
                    regexSuccess: string.Empty,
                    regexSuccessTimestampFormat: string.Empty));

                // The .temp file should be cleaned up on success
                ClassicAssert.IsFalse(File.Exists(srcPath + ".temp"),
                    "temp scanner file should be deleted at the end of the run");
            }
            finally
            {
                try { File.Delete(srcPath); } catch { /* best effort */ }
                try { File.Delete(srcPath + ".temp"); } catch { /* best effort */ }
            }
        }

        [Test]
        public void RunLogFileTest_EmptySourceFile_DoesNotCrash()
        {
            string srcPath = Path.Combine(Path.GetTempPath(), "ipban_logtest_empty_" + Guid.NewGuid().ToString("N") + ".log");
            File.WriteAllText(srcPath, string.Empty);
            try
            {
                Assert.DoesNotThrow(() => IPBanLogFileTester.RunLogFileTest(
                    fileName: srcPath,
                    regexFailure: @"(?<ipaddress>\S+)",
                    regexFailureTimestampFormat: string.Empty,
                    regexSuccess: string.Empty,
                    regexSuccessTimestampFormat: string.Empty));
            }
            finally
            {
                try { File.Delete(srcPath); } catch { /* best effort */ }
                try { File.Delete(srcPath + ".temp"); } catch { /* best effort */ }
            }
        }
    }

    // -------------------- IPBanNullFirewall --------------------

    [TestFixture]
    public sealed class IPBanNullFirewallTests
    {
        [Test]
        public async Task AllBlockAndAllowMethodsReturnTrueWithoutDoingAnything()
        {
            // The NullFirewall is intentionally a no-op for performance benchmarking. Every
            // mutating method should return true (success) and have no observable effect.
            using var fw = new IPBanNullFirewall();

            ClassicAssert.IsTrue(await fw.AllowIPAddresses(new[] { "1.2.3.4" }));
            ClassicAssert.IsTrue(await fw.AllowIPAddresses("AllowPrefix",
                new[] { IPAddressRange.Parse("1.2.3.0/24") }));
            ClassicAssert.IsTrue(await fw.BlockIPAddresses(null, new[] { "5.6.7.8" }));
            ClassicAssert.IsTrue(await fw.BlockIPAddressesDelta(null, new[]
            {
                new IPBanFirewallIPAddressDelta { Added = true, IPAddress = "9.9.9.9" }
            }));
            ClassicAssert.IsTrue(await fw.BlockIPAddresses("BlockPrefix",
                new[] { IPAddressRange.Parse("10.10.10.0/24") }, null));
        }

        [Test]
        public void EnumerationMethodsAllReturnEmpty()
        {
            using var fw = new IPBanNullFirewall();
            CollectionAssert.IsEmpty(fw.EnumerateAllowedIPAddresses());
            CollectionAssert.IsEmpty(fw.EnumerateBannedIPAddresses());
            CollectionAssert.IsEmpty(fw.EnumerateIPAddresses());
            CollectionAssert.IsEmpty(fw.GetRuleNames());
        }

        [Test]
        public void DeleteRuleReturnsFalse()
        {
            using var fw = new IPBanNullFirewall();
            ClassicAssert.IsFalse(fw.DeleteRule("anything"));
        }

        [Test]
        public void GetPortsReturnsNull()
        {
            using var fw = new IPBanNullFirewall();
            ClassicAssert.IsNull(fw.GetPorts("anything"));
        }

        [Test]
        public void TruncateIsNoOp()
        {
            using var fw = new IPBanNullFirewall();
            Assert.DoesNotThrow(() => fw.Truncate());
        }

        [Test]
        public void CompileReturnsEmptyMemoryFirewall()
        {
            using var fw = new IPBanNullFirewall();
            using var compiled = fw.Compile();
            ClassicAssert.IsNotNull(compiled);
            ClassicAssert.IsInstanceOf<IPBanMemoryFirewall>(compiled);
            CollectionAssert.IsEmpty(compiled.EnumerateBannedIPAddresses());
        }

        [Test]
        public void Query_OnNullFirewall_ReturnsNeitherBlockedNorAllowed()
        {
            // The Null firewall delegates Query to its base (IPBanBaseFirewall) which returns
            // a (blocked, allowed, ruleName) tuple per query — for an IP with no rules the
            // tuple is (false, false, null). Verify that exact shape rather than expecting
            // an empty collection.
            using var fw = new IPBanNullFirewall();
            var result = fw.Query(new[] { new IPEndPoint(IPAddress.Parse("1.2.3.4"), 0) });

            ClassicAssert.AreEqual(1, result.Count, "Query returns one entry per input endpoint");
            ClassicAssert.IsFalse(result[0].blocked, "Null firewall has no block rules");
            ClassicAssert.IsFalse(result[0].allowed, "Null firewall has no allow rules");
            ClassicAssert.IsNull(result[0].ruleName, "no matching rule means no name");
        }
    }
}
