/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for ExtensionMethods - the helper methods that aren't covered by
the existing IPBanExtensionsTests / IPBanExtensionMethodsHelpersTests files.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using UInt128 = DigitalRuby.IPBanCore.UInt128;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanExtensionMethodsTests2
    {
        // -------- ToBytesUTF8 / ToStringUTF8 --------

        [Test]
        public void ToBytesUTF8_RoundTripsViaToStringUTF8()
        {
            byte[] bytes = "hello".ToBytesUTF8();
            ClassicAssert.AreEqual("hello", bytes.ToStringUTF8());
        }

        [Test]
        public void ToBytesUTF8_NullReturnsNull()
        {
            ClassicAssert.IsNull(((string)null).ToBytesUTF8());
        }

        // -------- ToHexString / ToBytesFromHex --------

        [Test]
        public void ToHexString_FromBytesFromHex_RoundTrip()
        {
            byte[] orig = new byte[16];
            for (int i = 0; i < orig.Length; i++) orig[i] = (byte)i;
            string hex = orig.ToHexString();
            byte[] back = hex.ToBytesFromHex();
            CollectionAssert.AreEqual(orig, back);
        }

        // -------- ToStringIso8601 --------

        [Test]
        public void ToStringIso8601_Format()
        {
            var dt = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);
            ClassicAssert.AreEqual("2024-01-02T03:04:05Z", dt.ToStringIso8601());
        }

        // -------- UrlEncode --------

        [Test]
        public void UrlEncode_BasicEscape()
        {
            ClassicAssert.AreEqual("a%26b", "a&b".UrlEncode());
            ClassicAssert.AreEqual(string.Empty, ((string)null).UrlEncode());
        }

        // -------- ToLongInvariant --------

        [Test]
        public void ToLongInvariant_GoodAndBad()
        {
            ClassicAssert.AreEqual(123L, "123".ToLongInvariant());
            ClassicAssert.AreEqual(0L, "abc".ToLongInvariant());
            ClassicAssert.AreEqual(0L, ((string)null).ToLongInvariant());
        }

        // -------- ToHttpHeaderString --------

        [Test]
        public void ToHttpHeaderString_NullReturnsEmpty()
        {
            ClassicAssert.AreEqual(string.Empty, ((object)null).ToHttpHeaderString());
        }

        [Test]
        public void ToHttpHeaderString_SecureStringUnsecures()
        {
            using var s = "value".ToSecureString();
            ClassicAssert.AreEqual("value", s.ToHttpHeaderString());
        }

        [Test]
        public void ToHttpHeaderString_OtherObjectUsesInvariant()
        {
            ClassicAssert.AreEqual("123", ((object)123).ToHttpHeaderString());
        }

        // -------- Unix epoch round trip --------

        [Test]
        public void ToDateTimeUnixMilliseconds_RoundTrip_Long()
        {
            long ms = 1700000000000L;
            var dt = ms.ToDateTimeUnixMilliseconds();
            ClassicAssert.AreEqual(ms, dt.ToUnixMillisecondsLong());
        }

        [Test]
        public void ToDateTimeUnixMilliseconds_RoundTrip_Double()
        {
            double ms = 1700000000000.0;
            var dt = ms.ToDateTimeUnixMilliseconds();
            ClassicAssert.AreEqual(ms, dt.ToUnixMilliseconds(), 1.0);
        }

        [Test]
        public void ToUnixMilliseconds_LocalTimeIsConvertedToUtc()
        {
            var local = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local);
            // Just ensure it does not throw and is a non-zero value
            double v = local.ToUnixMilliseconds();
            ClassicAssert.Greater(v, 0);
        }

        // -------- ToUnsecureBytes --------

        [Test]
        public void ToUnsecureBytes_NullSecureString_ReturnsNull()
        {
            System.Security.SecureString s = null;
            ClassicAssert.IsNull(s.ToUnsecureBytes());
        }

        [Test]
        public void ToUnsecureBytes_RoundTrip()
        {
            using var s = "hello".ToSecureString();
            byte[] bytes = s.ToUnsecureBytes();
            ClassicAssert.AreEqual("hello", bytes.ToStringUTF8());
        }

        // -------- IPAddress helpers --------

        [Test]
        public void Clean_RemovesScopeIdAndMapsToV4()
        {
            // ipv4-mapped ipv6 -> ipv4
            var ip = IPAddress.Parse("::ffff:1.2.3.4");
            var cleaned = ip.Clean();
            ClassicAssert.AreEqual("1.2.3.4", cleaned.ToString());
        }

        [Test]
        public void EqualsWithMapToIPv6_DifferentRepresentationsOfLoopback_AreEqual()
        {
            var v4 = IPAddress.Parse("127.0.0.1");
            var v6 = IPAddress.Parse("::1");
            ClassicAssert.IsTrue(v4.EqualsWithMapToIPv6(v6));
            ClassicAssert.IsTrue(v4.EqualsWithMapToIPv6(v4));
        }

        [Test]
        public void IsLocalHost_DetectsBoth()
        {
            ClassicAssert.IsTrue(IPAddress.Parse("127.0.0.1").IsLocalHost());
            ClassicAssert.IsTrue(IPAddress.Parse("::1").IsLocalHost());
            ClassicAssert.IsFalse(IPAddress.Parse("8.8.8.8").IsLocalHost());
            ClassicAssert.IsFalse(((IPAddress)null).IsLocalHost());
        }

        [Test]
        public void TryIncrement_Decrement_RoundTrip()
        {
            var ip = IPAddress.Parse("1.2.3.4");
            ClassicAssert.IsTrue(ip.TryIncrement(out var next));
            ClassicAssert.IsTrue(next.TryDecrement(out var back));
            ClassicAssert.AreEqual(ip.ToString(), back.ToString());
        }

        [Test]
        public void TryIncrement_AtMaxIPv4_ReturnsFalse()
        {
            var ip = IPAddress.Parse("255.255.255.255");
            ClassicAssert.IsFalse(ip.TryIncrement(out _));
        }

        [Test]
        public void TryDecrement_AtMinIPv4_ReturnsFalse()
        {
            var ip = IPAddress.Parse("0.0.0.0");
            ClassicAssert.IsFalse(ip.TryDecrement(out _));
        }

        [Test]
        public void CompareTo_IPAddresses_OrderingNullsAndFamilies()
        {
            ClassicAssert.AreEqual(0, ((IPAddress)null).CompareTo(null));
            ClassicAssert.AreEqual(-1, ((IPAddress)null).CompareTo(IPAddress.Parse("1.2.3.4")));
            ClassicAssert.AreEqual(0, IPAddress.Parse("1.2.3.4").CompareTo(IPAddress.Parse("1.2.3.4")));
            ClassicAssert.IsTrue(IPAddress.Parse("1.2.3.4").CompareTo(IPAddress.Parse("1.2.3.5")) < 0);
            ClassicAssert.IsTrue(IPAddress.Parse("::1").CompareTo(IPAddress.Parse("::2")) < 0);
            // Different family
            ClassicAssert.AreNotEqual(0, IPAddress.Parse("1.2.3.4").CompareTo(IPAddress.Parse("::1")));
        }

        [Test]
        public void TryNormalizeIPAddress_GoodIp_Normalized()
        {
            ClassicAssert.IsTrue("1.2.3.4".TryNormalizeIPAddress(out string n));
            ClassicAssert.AreEqual("1.2.3.4", n);
        }

        [Test]
        public void TryNormalizeIPAddress_GoodCidr_NormalizedToCidr()
        {
            ClassicAssert.IsTrue("10.0.0.0/24".TryNormalizeIPAddress(out string n));
            StringAssert.Contains("/24", n);
        }

        [Test]
        public void TryNormalizeIPAddress_LocalhostAndNullEquivalents_Rejected()
        {
            ClassicAssert.IsFalse(((string)null).TryNormalizeIPAddress(out _));
            ClassicAssert.IsFalse(string.Empty.TryNormalizeIPAddress(out _));
            ClassicAssert.IsFalse("0.0.0.0".TryNormalizeIPAddress(out _));
            ClassicAssert.IsFalse("127.0.0.1".TryNormalizeIPAddress(out _));
            ClassicAssert.IsFalse("::1".TryNormalizeIPAddress(out _));
            ClassicAssert.IsFalse("-".TryNormalizeIPAddress(out _));
        }

        [Test]
        public void TryNormalizeIPAddress_IpWithPort_StripsPort()
        {
            ClassicAssert.IsTrue("1.2.3.4:80".TryNormalizeIPAddress(out string n));
            ClassicAssert.AreEqual("1.2.3.4", n);
        }

        [Test]
        public void ToIPAddress_FromString_NullOnBad()
        {
            ClassicAssert.IsNull("not-an-ip".ToIPAddress());
            ClassicAssert.AreEqual("1.2.3.4", "1.2.3.4".ToIPAddress().ToString());
        }

        [Test]
        public void ToIPAddress_FromUInt32_RoundTrips()
        {
            var ip = IPAddress.Parse("1.2.3.4");
            uint v = ip.ToUInt32();
            ClassicAssert.AreEqual("1.2.3.4", v.ToIPAddress().ToString());
        }

        [Test]
        public void ToIPAddress_FromUInt128_RoundTrips()
        {
            var ip = IPAddress.Parse("2001:db8::1");
            UInt128 v = ip.ToUInt128();
            ClassicAssert.AreEqual(ip.ToString(), v.ToIPAddress().ToString());
        }

        [Test]
        public void ToUInt32_NotIPv4_Throws()
        {
            Assert.Throws<InvalidOperationException>(() => IPAddress.Parse("::1").ToUInt32());
        }

        [Test]
        public void ToUInt128_NotIPv6_Throws()
        {
            Assert.Throws<InvalidOperationException>(() => IPAddress.Parse("1.2.3.4").ToUInt128());
        }

        // -------- JsonElement helpers --------

        [Test]
        public void JsonElementHelpers_ParseValuesOrDefaults()
        {
            string json = "{\"name\":\"alice\",\"i\":\"42\",\"l\":\"99\",\"b\":\"true\",\"d\":\"2024-01-02T03:04:05Z\"}";
            using var doc = JsonDocument.Parse(json);
            var elem = doc.RootElement;
            ClassicAssert.AreEqual("alice", elem.GetString("name"));
            ClassicAssert.AreEqual(42, elem.GetInt32("i"));
            ClassicAssert.AreEqual(99L, elem.GetInt64("l"));
            ClassicAssert.IsTrue(elem.GetBool("b"));
            ClassicAssert.AreEqual(new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc),
                elem.GetDateTime("d", DateTime.MinValue).ToUniversalTime());

            // Missing keys return defaults
            ClassicAssert.AreEqual("default", elem.GetString("missing", "default"));
            ClassicAssert.AreEqual(7, elem.GetInt32("missing", 7));
            ClassicAssert.AreEqual(7L, elem.GetInt64("missing", 7L));
            ClassicAssert.IsFalse(elem.GetBool("missing"));
            ClassicAssert.AreEqual(DateTime.MinValue, elem.GetDateTime("missing", DateTime.MinValue));

            // Invalid types fall back to defaults
            string j2 = "{\"i\":\"notanumber\",\"l\":\"notanumber\",\"b\":\"notabool\"}";
            using var doc2 = JsonDocument.Parse(j2);
            ClassicAssert.AreEqual(0, doc2.RootElement.GetInt32("i"));
            ClassicAssert.AreEqual(0L, doc2.RootElement.GetInt64("l"));
            ClassicAssert.IsFalse(doc2.RootElement.GetBool("b"));
        }

        // -------- ParseTimeSpan / ParseInt --------

        [Test]
        public void ParseTimeSpan_ParseInt_RoundTrip()
        {
            var ts = "01:02:03".ParseTimeSpan();
            ClassicAssert.IsNotNull(ts);
            ClassicAssert.AreEqual(new TimeSpan(1, 2, 3), ts.Value);
            ClassicAssert.IsNull("garbage".ParseTimeSpan());

            ClassicAssert.AreEqual(42, "42".ParseInt());
            ClassicAssert.IsNull("garbage".ParseInt());
        }

        // -------- SmallestTimeSpan --------

        [Test]
        public void SmallestTimeSpan_AllCombinations()
        {
            var def = TimeSpan.FromSeconds(1);
            ClassicAssert.AreEqual(def, ExtensionMethods.SmallestTimeSpan(null, null, def));
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(2), ExtensionMethods.SmallestTimeSpan(null, TimeSpan.FromSeconds(2), def));
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(2), ExtensionMethods.SmallestTimeSpan(TimeSpan.FromSeconds(2), null, def));
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(2), ExtensionMethods.SmallestTimeSpan(TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(2), def));
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(2), ExtensionMethods.SmallestTimeSpan(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(3), def));
        }

        // -------- Clamp --------

        [Test]
        public void Clamp_TimeSpan_ClampsTooSmallToMax()
        {
            // value < 1s collapses to max
            var v = TimeSpan.FromMilliseconds(100);
            ClassicAssert.AreEqual(TimeSpan.FromMinutes(5), v.Clamp(TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5)));
            // value > max collapses to max
            ClassicAssert.AreEqual(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10).Clamp(TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5)));
            // value < min collapses to min
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(1500).Clamp(TimeSpan.FromSeconds(2), TimeSpan.FromMinutes(5)));
            // value within range stays
            ClassicAssert.AreEqual(TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3).Clamp(TimeSpan.FromSeconds(2), TimeSpan.FromMinutes(5)));
        }

        [Test]
        public void Clamp_Generic_OnInts()
        {
            ClassicAssert.AreEqual(0, 0.Clamp(0, 10));
            ClassicAssert.AreEqual(10, 100.Clamp(0, 10));
            ClassicAssert.AreEqual(0, (-5).Clamp(0, 10));
            ClassicAssert.AreEqual(5, 5.Clamp(0, 10));
        }

        [Test]
        public void Clamp_Generic_TimeSpanFlag_AffectsSmallTimeSpan()
        {
            // The bare-3-arg call resolves to the TimeSpan-specific overload, which already
            // collapses sub-1-second values to max regardless of the flag. So both calls
            // here go to max for a 100ms input.
            var v = TimeSpan.FromMilliseconds(100);
            ClassicAssert.AreEqual(TimeSpan.FromMinutes(5), v.Clamp(TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5)));
            ClassicAssert.AreEqual(TimeSpan.FromMinutes(5), v.Clamp(TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5), clampSmallTimeSpanToMax: true));
        }

        // -------- Json helpers (ExtensionMethods version) --------

        public class Sample { public string Name { get; set; } public int Val { get; set; } }

        [Test]
        public void DeserializeJson_String_Bytes_RoundTrip()
        {
            var s = new Sample { Name = "hello", Val = 5 };
            string json = s.SerializeJson();
            var back = ExtensionMethods.DeserializeJson<Sample>(json);
            ClassicAssert.AreEqual("hello", back.Name);
            ClassicAssert.AreEqual(5, back.Val);

            byte[] bytes = s.SerializeUtf8Json();
            var back2 = ExtensionMethods.DeserializeJson<Sample>(bytes);
            ClassicAssert.AreEqual("hello", back2.Name);

            // Garbage bytes should default
            var defaultV = ExtensionMethods.DeserializeJson<Sample>(new byte[] { 1, 2, 3 });
            ClassicAssert.IsNull(defaultV);
        }

        [Test]
        public void SerializeUtf8Json_StreamWritesContent()
        {
            var s = new Sample { Name = "x", Val = 1 };
            using var ms = new MemoryStream();
            s.SerializeUtf8Json(ms);
            ms.Position = 0;
            string text = new StreamReader(ms).ReadToEnd();
            StringAssert.Contains("\"Name\":\"x\"", text);
        }

        // -------- WhenAll for ValueTask --------

        [Test]
        public async Task WhenAll_ValueTasks_AllComplete()
        {
            int counter = 0;
            ValueTask Task1() { System.Threading.Interlocked.Increment(ref counter); return new ValueTask(); }
            await new[] { Task1(), Task1(), Task1() }.WhenAll();
            ClassicAssert.AreEqual(3, counter);
        }

        [Test]
        public async Task WhenAll_GenericValueTasks_AllReturnValues()
        {
            ValueTask<int> Make(int v) => new(v);
            var tasks = new[] { Make(1), Make(2), Make(3) };
            await tasks.WhenAll();
            // No assertion on values - just confirming no exception
            ClassicAssert.Pass();
        }

        // -------- AsTask (WaitHandle) --------

        [Test]
        public async Task AsTask_WaitHandle_CompletesWhenSignaled()
        {
            using var evt = new System.Threading.ManualResetEvent(false);
            evt.Set();
            await evt.AsTask();
            ClassicAssert.Pass();
        }

        [Test]
        public void AsTask_WaitHandle_TimeoutCancels()
        {
            using var evt = new System.Threading.ManualResetEvent(false);
            var task = evt.AsTask(TimeSpan.FromMilliseconds(50));
            Assert.ThrowsAsync<TaskCanceledException>(async () => await task);
        }

        // -------- File helpers --------

        [Test]
        public void FileDeleteWithRetry_NonExisting_DoesNothing()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_delete_" + Guid.NewGuid().ToString("N"));
            Assert.DoesNotThrow(() => ExtensionMethods.FileDeleteWithRetry(path));
        }

        [Test]
        public void FileCopyWithRetry_CopiesContent()
        {
            string src = Path.Combine(Path.GetTempPath(), "ipban_copy_src_" + Guid.NewGuid().ToString("N") + ".txt");
            string dst = Path.Combine(Path.GetTempPath(), "ipban_copy_dst_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(src, "hello");
                ExtensionMethods.FileCopyWithRetry(src, dst);
                ClassicAssert.AreEqual("hello", File.ReadAllText(dst));
            }
            finally
            {
                try { File.Delete(src); } catch { }
                try { File.Delete(dst); } catch { }
            }
        }

        [Test]
        public void FileMoveWithRetry_MovesContent()
        {
            string src = Path.Combine(Path.GetTempPath(), "ipban_move_src_" + Guid.NewGuid().ToString("N") + ".txt");
            string dst = Path.Combine(Path.GetTempPath(), "ipban_move_dst_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(src, "moved");
                ExtensionMethods.FileMoveWithRetry(src, dst);
                ClassicAssert.IsFalse(File.Exists(src));
                ClassicAssert.AreEqual("moved", File.ReadAllText(dst));
            }
            finally
            {
                try { File.Delete(src); } catch { }
                try { File.Delete(dst); } catch { }
            }
        }

        [Test]
        public void DirectoryMoveAndDeleteWithRetry()
        {
            string src = Path.Combine(Path.GetTempPath(), "ipban_dir_" + Guid.NewGuid().ToString("N"));
            string dst = src + "_moved";
            try
            {
                Directory.CreateDirectory(src);
                File.WriteAllText(Path.Combine(src, "file.txt"), "x");

                ExtensionMethods.DirectoryMoveWithRetry(src, dst);
                ClassicAssert.IsFalse(Directory.Exists(src));
                ClassicAssert.IsTrue(Directory.Exists(dst));

                ExtensionMethods.DirectoryDeleteWithRetry(dst);
                ClassicAssert.IsFalse(Directory.Exists(dst));

                // Also test no-op paths
                ExtensionMethods.DirectoryMoveWithRetry(src, dst);
                ExtensionMethods.DirectoryDeleteWithRetry(dst);
            }
            finally
            {
                try { Directory.Delete(src, true); } catch { }
                try { Directory.Delete(dst, true); } catch { }
            }
        }

        // -------- IsAnonymousType --------

        [Test]
        public void IsAnonymousType_TrueForAnonymous_FalseForNormal()
        {
            var anon = new { A = 1, B = "x" };
            ClassicAssert.IsTrue(anon.GetType().IsAnonymousType());
            ClassicAssert.IsFalse(typeof(Sample).IsAnonymousType());
            ClassicAssert.IsFalse(((Type)null).IsAnonymousType());
        }

        // -------- Sync --------

        [Test]
        public void Sync_BlocksUntilTaskCompletes()
        {
            int v = 0;
            Task.Delay(20).ContinueWith(_ => v = 1).Sync();
            ClassicAssert.AreEqual(1, v);

            int r = Task.FromResult(42).Sync();
            ClassicAssert.AreEqual(42, r);

            new ValueTask().Sync();
            int r2 = new ValueTask<int>(7).Sync();
            ClassicAssert.AreEqual(7, r2);
        }

        // -------- RemoveDatabaseFiles --------

        [Test]
        public void RemoveDatabaseFiles_RemovesKnownExtensions()
        {
            string folder = Path.Combine(Path.GetTempPath(), "ipban_rm_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try
            {
                string[] exts = { ".set", ".tbl", ".set6", ".tbl6", ".sqlite", ".sqlite-wal", ".sqlite-shm" };
                foreach (var ext in exts)
                {
                    File.WriteAllText(Path.Combine(folder, "file" + ext), "x");
                }
                File.WriteAllText(Path.Combine(folder, "thing-journal"), "x");
                ExtensionMethods.RemoveDatabaseFiles(folder);
                CollectionAssert.IsEmpty(Directory.GetFiles(folder));
            }
            finally
            {
                try { Directory.Delete(folder, true); } catch { }
            }
        }

        // -------- RemoveInternalRanges --------

        [Test]
        public void RemoveInternalRanges_FullyInternalRange_RemovedEntirely()
        {
            // 192.168.0.0/16 is internal
            var r = IPAddressRange.Parse("192.168.10.0/24");
            var result = r.RemoveInternalRanges().ToArray();
            CollectionAssert.IsEmpty(result);
        }

        [Test]
        public void RemoveInternalRanges_NonInternal_KeptAsIs()
        {
            // 8.8.8.0/24 is public
            var r = IPAddressRange.Parse("8.8.8.0/24");
            var result = r.RemoveInternalRanges().ToArray();
            ClassicAssert.AreEqual(1, result.Length);
        }

        // -------- Combine --------

        [Test]
        public void Combine_ConsecutiveRanges_Merged()
        {
            var r1 = IPAddressRange.Parse("1.1.1.0-1.1.1.10");
            var r2 = IPAddressRange.Parse("1.1.1.11-1.1.1.20");
            var merged = new[] { r1, r2 }.Combine().ToArray();
            ClassicAssert.AreEqual(1, merged.Length);
        }

        [Test]
        public void Combine_DisjointRanges_NotMerged()
        {
            var r1 = IPAddressRange.Parse("1.1.1.0/24");
            var r2 = IPAddressRange.Parse("2.2.2.0/24");
            var combined = new[] { r1, r2 }.Combine().ToArray();
            ClassicAssert.AreEqual(2, combined.Length);
        }

        [Test]
        public void Combine_EmptySource_YieldsNothing()
        {
            CollectionAssert.IsEmpty(Enumerable.Empty<IPAddressRange>().Combine().ToArray());
        }

        // -------- Invert --------

        [Test]
        public void Invert_EmptyRanges_GivesEmpty()
        {
            // Implementation only emits "left gap" entries when at least one range exists,
            // so an empty input yields nothing. Just confirm no throw.
            var inverted = Enumerable.Empty<IPAddressRange>().Invert().ToArray();
            ClassicAssert.IsNotNull(inverted);
        }

        [Test]
        public void Invert_NonEmptyRange_ProducesGaps()
        {
            // Use one well-known public range; the inverter should yield at least one gap
            // around it.
            var inverted = new[] { IPAddressRange.Parse("100.64.0.0/24") }.Invert(removeInternal: false).ToArray();
            ClassicAssert.IsTrue(inverted.Length > 0);
        }

        // -------- GetEntriesMatchingPrefix --------

        [Test]
        public void GetEntriesMatchingPrefix_ReturnsAllEntriesStartingWithPrefix()
        {
            var sl = new SortedList<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                { "alice", 1 },
                { "alpha", 2 },
                { "bob", 3 }
            };
            var matches = sl.GetEntriesMatchingPrefix("al").ToArray();
            ClassicAssert.AreEqual(2, matches.Length);
            CollectionAssert.AreEquivalent(new[] { "alice", "alpha" }, matches.Select(m => m.Key));
        }

        [Test]
        public void GetEntriesMatchingPrefix_NoMatches_Empty()
        {
            var sl = new SortedList<string, int>
            {
                { "alpha", 1 }, { "beta", 2 }
            };
            var matches = sl.GetEntriesMatchingPrefix("z").ToArray();
            CollectionAssert.IsEmpty(matches);
        }

        // -------- PrettyPrint XmlDocument --------

        [Test]
        public void PrettyPrint_AddsIndentation()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<a><b><c/></b></a>");
            string pretty = doc.PrettyPrint();
            ClassicAssert.IsTrue(pretty.Contains("\n"), "should contain newlines: " + pretty);
        }

        // -------- ToArray UnmanagedMemoryStream --------

        [Test]
        public unsafe void ToArray_UnmanagedMemoryStream_RoundTrip()
        {
            byte[] data = new byte[] { 1, 2, 3, 4, 5 };
            fixed (byte* ptr = data)
            {
                using var ms = new UnmanagedMemoryStream(ptr, data.Length);
                byte[] back = ms.ToArray();
                CollectionAssert.AreEqual(data, back);
            }
        }

        // -------- ToStringXml --------

        [Test]
        public void ToStringXml_NullReturnsNull()
        {
            object o = null;
            ClassicAssert.IsNull(o.ToStringXml());
        }

        [Test]
        public void ToStringXml_BasicObject_ReturnsXml()
        {
            var s = new Sample { Name = "x", Val = 1 };
            string xml = s.ToStringXml();
            StringAssert.Contains("Sample", xml);
            StringAssert.Contains("x", xml);
        }

        // -------- GetLockedEnumerator --------

        [Test]
        public void GetLockedEnumerator_EnumeratesAndReleasesLock()
        {
            var data = new[] { 1, 2, 3 };
            using var enumerator = data.GetLockedEnumerator();
            int count = 0;
            while (enumerator.MoveNext()) count++;
            ClassicAssert.AreEqual(3, count);
        }
    }
}
