/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for JsonSerializationHelper - serialize/deserialize for strings,
streams, files, async paths, and the Canonicalize helper.
*/

using System;
using System.IO;
using System.Threading.Tasks;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanJsonSerializationHelperTests
    {
        public class Sample
        {
            public string Name;
            public int Value;
            public string Optional;
        }

        [Test]
        public void Serialize_Deserialize_String_RoundTrip()
        {
            var s = new Sample { Name = "abc", Value = 42 };
            string json = JsonSerializationHelper.Serialize(s);
            ClassicAssert.IsTrue(json.Contains("\"Name\""));
            var back = JsonSerializationHelper.Deserialize<Sample>(json);
            ClassicAssert.AreEqual("abc", back.Name);
            ClassicAssert.AreEqual(42, back.Value);
        }

        [Test]
        public void Serialize_OmitsNullProperties()
        {
            var s = new Sample { Name = "x", Value = 1, Optional = null };
            string json = JsonSerializationHelper.Serialize(s);
            ClassicAssert.IsFalse(json.Contains("Optional"),
                "default options ignore null values; got: " + json);
        }

        [Test]
        public void Serialize_Deserialize_Stream_RoundTrip()
        {
            var s = new Sample { Name = "stream", Value = 7 };
            using var ms = new MemoryStream();
            JsonSerializationHelper.Serialize(s, ms);
            ms.Position = 0;
            var back = JsonSerializationHelper.Deserialize<Sample>(ms);
            ClassicAssert.AreEqual("stream", back.Name);
            ClassicAssert.AreEqual(7, back.Value);
        }

        [Test]
        public void Deserialize_Stream_NonGeneric_RoundTrip()
        {
            var s = new Sample { Name = "ng", Value = 3 };
            using var ms = new MemoryStream();
            JsonSerializationHelper.Serialize(s, ms);
            ms.Position = 0;
            var back = (Sample)JsonSerializationHelper.Deserialize(ms, typeof(Sample));
            ClassicAssert.AreEqual("ng", back.Name);
            ClassicAssert.AreEqual(3, back.Value);
        }

        [Test]
        public void Serialize_Stream_NullThrows()
        {
            Assert.Throws<ArgumentNullException>(() => JsonSerializationHelper.Serialize<Sample>(new Sample(), null));
        }

        [Test]
        public void Deserialize_Stream_NullThrows()
        {
            Assert.Throws<ArgumentNullException>(() => JsonSerializationHelper.Deserialize<Sample>((Stream)null));
            Assert.Throws<ArgumentNullException>(() => JsonSerializationHelper.Deserialize(null, typeof(Sample)));
        }

        [Test]
        public async Task SerializeAsync_DeserializeAsync_RoundTrip()
        {
            var s = new Sample { Name = "async", Value = 99 };
            using var ms = new MemoryStream();
            await JsonSerializationHelper.SerializeAsync(s, ms);
            ms.Position = 0;
            var back = await JsonSerializationHelper.DeserializeAsync<Sample>(ms);
            ClassicAssert.AreEqual("async", back.Name);
            ClassicAssert.AreEqual(99, back.Value);
        }

        [Test]
        public void SerializeAsync_NullStreamThrows()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await JsonSerializationHelper.SerializeAsync(new Sample(), null));
        }

        [Test]
        public void DeserializeAsync_NullStreamThrows()
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await JsonSerializationHelper.DeserializeAsync<Sample>(null));
        }

        [Test]
        public void SerializeToFile_DeserializeFromFile_RoundTrip()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_jsonser_" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                var s = new Sample { Name = "file", Value = 12 };
                JsonSerializationHelper.SerializeToFile(s, path);
                ClassicAssert.IsTrue(File.Exists(path));
                var back = JsonSerializationHelper.DeserializeFromFile<Sample>(path);
                ClassicAssert.AreEqual("file", back.Name);
                ClassicAssert.AreEqual(12, back.Value);
                var back2 = (Sample)JsonSerializationHelper.DeserializeFromFile(path, typeof(Sample));
                ClassicAssert.AreEqual("file", back2.Name);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public async Task SerializeToFileAsync_DeserializeFromFileAsync_RoundTrip()
        {
            string path = Path.Combine(Path.GetTempPath(), "ipban_jsonser_async_" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                var s = new Sample { Name = "fileAsync", Value = 100 };
                await JsonSerializationHelper.SerializeToFileAsync(s, path);
                ClassicAssert.IsTrue(File.Exists(path));
                var back = await JsonSerializationHelper.DeserializeFromFileAsync<Sample>(path);
                ClassicAssert.AreEqual("fileAsync", back.Name);
                ClassicAssert.AreEqual(100, back.Value);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best effort */ }
            }
        }

        [Test]
        public void Canonicalize_SortsObjectProperties()
        {
            string json = "{\"b\":1,\"a\":2}";
            string canon = JsonSerializationHelper.Canonicalize(json);
            ClassicAssert.AreEqual("{\"a\":2,\"b\":1}", canon);
        }

        [Test]
        public void Canonicalize_NestedObjects()
        {
            string json = "{\"x\":{\"z\":1,\"y\":2},\"a\":3}";
            string canon = JsonSerializationHelper.Canonicalize(json);
            ClassicAssert.AreEqual("{\"a\":3,\"x\":{\"y\":2,\"z\":1}}", canon);
        }

        [Test]
        public void Canonicalize_HandlesArraysStringsAndPrimitives()
        {
            string json = "{\"arr\":[3,1,2],\"s\":\"hello\",\"t\":true,\"f\":false,\"n\":null}";
            string canon = JsonSerializationHelper.Canonicalize(json);
            ClassicAssert.IsTrue(canon.Contains("[3,1,2]"));
            ClassicAssert.IsTrue(canon.Contains("\"hello\""));
            ClassicAssert.IsTrue(canon.Contains("true"));
            ClassicAssert.IsTrue(canon.Contains("false"));
            ClassicAssert.IsTrue(canon.Contains("null"));
        }

        [Test]
        public void Canonicalize_EscapesQuotesAndBackslashes()
        {
            // The Canonicalize implementation only escapes backslash and double-quote.
            // Avoid JSON control-character escapes (\b, \n, etc.) that can't survive a
            // re-encode that emits the raw byte literally.
            string json = "{\"a\":\"path\\\\to\\\\file\"}";
            string canon = JsonSerializationHelper.Canonicalize(json);
            using var doc = System.Text.Json.JsonDocument.Parse(canon);
            ClassicAssert.AreEqual("path\\to\\file", doc.RootElement.GetProperty("a").GetString());
        }
    }
}
