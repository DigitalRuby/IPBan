/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for the safe json value helpers in JsonValueHelpers.cs and the TryParse helpers in
JsonSerializationHelper. None of these may throw for missing properties, wrong json types, json null,
non-object/non-array receivers or invalid json text.
*/

using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

using DigitalRuby.IPBanCore;

using NUnit.Framework;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanJsonValueTests
    {
        private const string sampleJson = """
        {
            "str": "hello",
            "emptyStr": "",
            "intNum": 587,
            "intStr": "587",
            "negNum": -12,
            "negStr": "-12",
            "bigNum": 9007199254740993,
            "floatNum": 1.5,
            "wholeFloat": 5.0,
            "expNum": 1e3,
            "boolTrue": true,
            "boolFalse": false,
            "boolStr": "TRUE",
            "boolOne": 1,
            "boolZero": "0",
            "nullValue": null,
            "date": "2024-01-02T03:04:05Z",
            "dateNoZone": "2024-01-02T03:04:05",
            "guid": "5977d81261a3072bfe4acbae78c4eab7",
            "enumName": "warn",
            "enumNum": 4,
            "obj": { "inner": "x", "deep": { "value": 7 } },
            "arr": [ 1, "two", { "three": 3 } ]
        }
        """;

        private enum TestLevel { None = 0, Info = 1, Debug = 2, Error = 3, Fatal = 4, Warn = 5 }

        private static JsonElement Element() => JsonSerializationHelper.TryParseElement(sampleJson);

        private static JsonNode Node() => JsonSerializationHelper.TryParseNode(sampleJson);

        // ---------------------------------------------------------------------
        // strings
        // ---------------------------------------------------------------------

        [TestCase("str", "hello")]
        [TestCase("emptyStr", "")]
        [TestCase("intNum", "587")]
        [TestCase("intStr", "587")]
        [TestCase("negNum", "-12")]
        [TestCase("floatNum", "1.5")]
        [TestCase("boolTrue", "true")]
        [TestCase("boolFalse", "false")]
        [TestCase("nullValue", null)]
        [TestCase("missing", null)]
        public void GetString_AllJsonTypes(string name, string expected)
        {
            Assert.That(Element().GetString(name), Is.EqualTo(expected), "element");
            Assert.That(Node().GetString(name), Is.EqualTo(expected), "node");
        }

        [Test]
        public void GetString_ObjectAndArray_ReturnJsonText()
        {
            Assert.That(Element().GetString("arr").Replace(" ", string.Empty), Is.EqualTo("[1,\"two\",{\"three\":3}]"));
            Assert.That(Node().GetString("arr").Replace(" ", string.Empty), Is.EqualTo("[1,\"two\",{\"three\":3}]"));
            Assert.That(Node().GetString("obj").Replace(" ", string.Empty), Does.StartWith("{\"inner\":\"x\""));
        }

        [Test]
        public void GetString_DefaultForMissingAndNull()
        {
            Assert.That(Element().GetString("missing", "d"), Is.EqualTo("d"));
            Assert.That(Element().GetString("nullValue", "d"), Is.EqualTo("d"));
            Assert.That(Node().GetString("missing", "d"), Is.EqualTo("d"));
            Assert.That(Node().GetString("nullValue", "d"), Is.EqualTo("d"));
        }

        // ---------------------------------------------------------------------
        // numbers
        // ---------------------------------------------------------------------

        [TestCase("intNum", 587)]
        [TestCase("intStr", 587)]
        [TestCase("negNum", -12)]
        [TestCase("negStr", -12)]
        [TestCase("wholeFloat", 5)]
        [TestCase("expNum", 1000)]
        [TestCase("floatNum", -1)]   // not a whole number
        [TestCase("bigNum", -1)]     // out of int range
        [TestCase("str", -1)]
        [TestCase("boolTrue", -1)]
        [TestCase("nullValue", -1)]
        [TestCase("obj", -1)]
        [TestCase("missing", -1)]
        public void GetInt32_LenientOrDefault(string name, int expected)
        {
            Assert.That(Element().GetInt32(name, -1), Is.EqualTo(expected), "element");
            Assert.That(Node().GetInt32(name, -1), Is.EqualTo(expected), "node");
        }

        [Test]
        public void GetInt64_LargeAndNegative()
        {
            Assert.That(Element().GetInt64("bigNum"), Is.EqualTo(9007199254740993L));
            Assert.That(Node().GetInt64("bigNum"), Is.EqualTo(9007199254740993L));
            Assert.That(Element().GetInt64("negStr"), Is.EqualTo(-12L));
            Assert.That(Node().GetInt64("missing", 9), Is.EqualTo(9L));
        }

        [Test]
        public void GetDoubleAndDecimal()
        {
            Assert.That(Element().GetDouble("floatNum"), Is.EqualTo(1.5));
            Assert.That(Node().GetDouble("intStr"), Is.EqualTo(587.0));
            Assert.That(Element().GetDecimal("floatNum"), Is.EqualTo(1.5m));
            Assert.That(Node().GetDecimal("negStr"), Is.EqualTo(-12m));
            Assert.That(Node().GetDouble("str", 2.5), Is.EqualTo(2.5));
            Assert.That(Element().GetDecimal("obj", 3m), Is.EqualTo(3m));
        }

        // ---------------------------------------------------------------------
        // bools, dates, guids, enums
        // ---------------------------------------------------------------------

        [TestCase("boolTrue", true)]
        [TestCase("boolFalse", false)]
        [TestCase("boolStr", true)]
        [TestCase("boolOne", true)]
        [TestCase("boolZero", false)]
        public void GetBool_Lenient(string name, bool expected)
        {
            Assert.That(Element().GetBool(name, !expected), Is.EqualTo(expected), "element");
            Assert.That(Node().GetBool(name, !expected), Is.EqualTo(expected), "node");
        }

        [TestCase("str")]
        [TestCase("intNum")]
        [TestCase("nullValue")]
        [TestCase("missing")]
        [TestCase("arr")]
        public void GetBool_NotABool_Default(string name)
        {
            Assert.That(Element().GetBool(name, true), Is.True);
            Assert.That(Node().GetBool(name, true), Is.True);
        }

        [Test]
        public void GetDateTime()
        {
            var expected = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);
            Assert.That(Element().GetDateTime("date"), Is.EqualTo(expected));
            Assert.That(Element().GetDateTime("date").Kind, Is.EqualTo(DateTimeKind.Utc));
            Assert.That(Node().GetDateTime("date"), Is.EqualTo(expected));
            Assert.That(Element().GetDateTime("dateNoZone"), Is.EqualTo(new DateTime(2024, 1, 2, 3, 4, 5)));
            Assert.That(Element().GetDateTime("intNum", DateTime.MinValue), Is.EqualTo(DateTime.MinValue));
            Assert.That(Node().GetDateTime("boolTrue", DateTime.MaxValue), Is.EqualTo(DateTime.MaxValue));
            Assert.That(Element().GetDateTime("missing"), Is.EqualTo(default(DateTime)));
        }

        [Test]
        public void GetDateTime_NotAnObject_DoesNotThrow()
        {
            // the old helper called TryGetProperty without checking the element was an object
            Assert.That(Element().GetElement("arr").GetDateTime("date", DateTime.MinValue), Is.EqualTo(DateTime.MinValue));
            Assert.That(Element().GetElement("str").GetDateTime("date", DateTime.MinValue), Is.EqualTo(DateTime.MinValue));
        }

        [Test]
        public void GetGuid()
        {
            var expected = Guid.Parse("5977d81261a3072bfe4acbae78c4eab7");
            Assert.That(Element().GetGuid("guid"), Is.EqualTo(expected));
            Assert.That(Node().GetGuid("guid"), Is.EqualTo(expected));
            Assert.That(Node().GetGuid("str"), Is.EqualTo(Guid.Empty));
        }

        [Test]
        public void TryGetEnum()
        {
            Assert.That(Element().TryGetEnum("enumName", out TestLevel byName), Is.True);
            Assert.That(byName, Is.EqualTo(TestLevel.Warn));
            Assert.That(Node().TryGetEnum("enumNum", out TestLevel byNumber), Is.True);
            Assert.That(byNumber, Is.EqualTo(TestLevel.Fatal));
            Assert.That(Element().TryGetEnum("str", out TestLevel _), Is.False);
            Assert.That(Node().TryGetEnum("missing", out TestLevel missing), Is.False);
            Assert.That(missing, Is.EqualTo(TestLevel.None));
            Assert.That(Element().TryGetEnum("nullValue", out TestLevel _), Is.False);
        }

        // ---------------------------------------------------------------------
        // navigation
        // ---------------------------------------------------------------------

        [Test]
        public void Element_ChainedNavigation_NeverThrows()
        {
            var root = Element();
            Assert.That(root.GetElement("obj").GetElement("deep").GetInt32("value"), Is.EqualTo(7));
            Assert.That(root.GetElement("obj").GetString("inner"), Is.EqualTo("x"));
            Assert.That(root.GetElement("missing").GetElement("deeper").GetString("x", "d"), Is.EqualTo("d"));
            Assert.That(root.GetElement("str").GetElement("x").ValueKind, Is.EqualTo(JsonValueKind.Undefined));
            Assert.That(root.GetElement("arr").GetElement(1).GetStringValue(), Is.EqualTo("two"));
            Assert.That(root.GetElement("arr").GetElement(2).GetInt32("three"), Is.EqualTo(3));
            Assert.That(root.GetElement("arr").GetElement(99).ValueKind, Is.EqualTo(JsonValueKind.Undefined));
            Assert.That(root.GetElement("arr").GetElement(-1).ValueKind, Is.EqualTo(JsonValueKind.Undefined));
            Assert.That(root.GetElement("obj").GetElement(0).ValueKind, Is.EqualTo(JsonValueKind.Undefined));
        }

        [Test]
        public void Element_DefaultElement_AllReadsReturnDefaults()
        {
            JsonElement undefined = default;
            Assert.That(undefined.GetString("x"), Is.Null);
            Assert.That(undefined.GetInt32("x", 3), Is.EqualTo(3));
            Assert.That(undefined.GetBool("x", true), Is.True);
            Assert.That(undefined.GetDateTime("x"), Is.EqualTo(default(DateTime)));
            Assert.That(undefined.GetStringValue("d"), Is.EqualTo("d"));
            Assert.That(undefined.EnumerateArrayOrEmpty(), Is.Empty);
            Assert.That(undefined.EnumerateObjectOrEmpty(), Is.Empty);
            Assert.That(undefined.TryGetObjectProperty("x", out _), Is.False);
        }

        [Test]
        public void Element_TryGetObjectProperty_NonObject_False()
        {
            var root = Element();
            Assert.That(root.TryGetObjectProperty("str", out JsonElement str), Is.True);
            Assert.That(str.GetStringValue(), Is.EqualTo("hello"));
            Assert.That(root.GetElement("arr").TryGetObjectProperty("x", out _), Is.False);
            Assert.That(root.GetElement("intNum").TryGetObjectProperty("x", out _), Is.False);
            Assert.That(root.TryGetObjectProperty(null, out _), Is.False);
        }

        [Test]
        public void Element_EnumerateOrEmpty()
        {
            var root = Element();
            Assert.That(root.GetElement("arr").EnumerateArrayOrEmpty().Count(), Is.EqualTo(3));
            Assert.That(root.GetElement("obj").EnumerateArrayOrEmpty(), Is.Empty);
            Assert.That(root.GetElement("obj").EnumerateObjectOrEmpty().Select(p => p.Name), Is.EqualTo(new[] { "inner", "deep" }));
            Assert.That(root.GetElement("arr").EnumerateObjectOrEmpty(), Is.Empty);
        }

        [Test]
        public void Node_ChainedNavigation_NeverThrows()
        {
            var root = Node();
            Assert.That(root.GetNode("obj").GetNode("deep").GetInt32("value"), Is.EqualTo(7));
            Assert.That(root.GetNode("missing").GetNode("deeper").GetString("x", "d"), Is.EqualTo("d"));
            // the JsonNode indexer throws on a value or array, GetNode does not
            Assert.That(root.GetNode("str").GetNode("x"), Is.Null);
            Assert.That(root.GetNode("arr").GetNode("x"), Is.Null);
            Assert.That(root.GetNode("arr").GetNode(1).GetStringValue(), Is.EqualTo("two"));
            Assert.That(root.GetNode("arr").GetNode(5), Is.Null);
            Assert.That(root.GetNode("obj").GetNode(0), Is.Null);
            Assert.That(((JsonNode)null).GetNode("x"), Is.Null);
            Assert.That(((JsonNode)null).GetString("x", "d"), Is.EqualTo("d"));
            Assert.That(((JsonNode)null).EnumerateArrayOrEmpty(), Is.Empty);
            Assert.That(root.GetNode("arr").EnumerateArrayOrEmpty().Count(), Is.EqualTo(3));
            Assert.That(root.GetNode("obj").EnumerateObjectOrEmpty().Count(), Is.EqualTo(2));
            Assert.That(root.GetNode("arr").EnumerateObjectOrEmpty(), Is.Empty);
        }

        // ---------------------------------------------------------------------
        // nodes built in code (JsonValue wrapping clr values, not parsed json)
        // ---------------------------------------------------------------------

        [Test]
        public void Node_CodeCreatedValues()
        {
            var obj = new JsonObject
            {
                ["s"] = "text",
                ["i"] = 42,
                ["l"] = 9007199254740993L,
                ["d"] = 1.25,
                ["m"] = 2.5m,
                ["b"] = true,
                ["c"] = 'z',
                ["dt"] = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc),
                ["g"] = Guid.Parse("5977d81261a3072bfe4acbae78c4eab7"),
                ["n"] = null
            };
            Assert.That(obj.GetString("s"), Is.EqualTo("text"));
            Assert.That(obj.GetString("i"), Is.EqualTo("42"));
            Assert.That(obj.GetInt32("i"), Is.EqualTo(42));
            Assert.That(obj.GetInt64("l"), Is.EqualTo(9007199254740993L));
            Assert.That(obj.GetDouble("d"), Is.EqualTo(1.25));
            Assert.That(obj.GetDecimal("m"), Is.EqualTo(2.5m));
            Assert.That(obj.GetString("b"), Is.EqualTo("true"));
            Assert.That(obj.GetBool("b"), Is.True);
            Assert.That(obj.GetString("c"), Is.EqualTo("z"));
            Assert.That(obj.GetDateTime("dt"), Is.EqualTo(new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc)));
            Assert.That(obj.GetGuid("g"), Is.EqualTo(Guid.Parse("5977d81261a3072bfe4acbae78c4eab7")));
            Assert.That(obj.GetString("g"), Is.EqualTo("5977d812-61a3-072b-fe4a-cbae78c4eab7"));
            Assert.That(obj.GetString("n", "d"), Is.EqualTo("d"));
        }

        [Test]
        public void Node_StringWithEscapes_RoundTrips()
        {
            var obj = new JsonObject { ["p"] = "a\"b\\c" };
            Assert.That(obj.GetString("p"), Is.EqualTo("a\"b\\c"));
            var parsed = JsonSerializationHelper.TryParseNode(obj.ToJsonString());
            Assert.That(parsed.GetString("p"), Is.EqualTo("a\"b\\c"));
        }

        // ---------------------------------------------------------------------
        // writes
        // ---------------------------------------------------------------------

        [Test]
        public void TrySetProperty()
        {
            var obj = new JsonObject();
            Assert.That(obj.TrySetProperty("a", 1), Is.True);
            Assert.That(obj.GetInt32("a"), Is.EqualTo(1));
            Assert.That(obj.TrySetProperty("b", null), Is.True);
            Assert.That(obj.ContainsKey("b"), Is.True);
            Assert.That(((JsonNode)new JsonArray()).TrySetProperty("a", 1), Is.False);
            Assert.That(((JsonNode)JsonValue.Create(5)).TrySetProperty("a", 1), Is.False);
            Assert.That(((JsonNode)null).TrySetProperty("a", 1), Is.False);
            Assert.That(obj.TrySetProperty(null, 1), Is.False);
        }

        [Test]
        public void TrySetProperty_ValueWithParent_IsCopied()
        {
            // assigning a node that already belongs to another object throws InvalidOperationException
            var source = JsonSerializationHelper.ParseObjectOrNew("{\"child\":{\"x\":1}}");
            var target = new JsonObject();
            Assert.That(target.TrySetProperty("copy", source["child"]), Is.True);
            Assert.That(target.GetNode("copy").GetInt32("x"), Is.EqualTo(1));
            Assert.That(source.GetNode("child").GetInt32("x"), Is.EqualTo(1));
        }

        [Test]
        public void GetOrAddObjectAndArray()
        {
            var obj = JsonSerializationHelper.ParseObjectOrNew("{\"o\":{\"keep\":1},\"notObj\":5,\"a\":[1],\"notArr\":\"x\"}");
            Assert.That(obj.GetOrAddObject("o").GetInt32("keep"), Is.EqualTo(1));
            Assert.That(obj.GetOrAddObject("new"), Is.Not.Null);
            Assert.That(obj["new"], Is.InstanceOf<JsonObject>());
            obj.GetOrAddObject("notObj")["x"] = 2;
            Assert.That(obj.GetNode("notObj").GetInt32("x"), Is.EqualTo(2));
            Assert.That(obj.GetOrAddArray("a").Count, Is.EqualTo(1));
            obj.GetOrAddArray("notArr").Add(3);
            Assert.That(obj.GetNode("notArr").GetNode(0).GetInt32Value(), Is.EqualTo(3));
            Assert.That(() => ((JsonObject)null).GetOrAddObject("x"), Throws.ArgumentNullException);
        }

        // ---------------------------------------------------------------------
        // parsing
        // ---------------------------------------------------------------------

        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        [TestCase("{not json")]
        [TestCase("null")]
        public void TryParseNode_InvalidOrEmpty_Null(string json)
        {
            Assert.That(JsonSerializationHelper.TryParseNode(json), Is.Null);
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("{not json")]
        public void TryParseDocumentAndElement_InvalidOrEmpty(string json)
        {
            Assert.That(JsonSerializationHelper.TryParseDocument(json), Is.Null);
            Assert.That(JsonSerializationHelper.TryParseElement(json).ValueKind, Is.EqualTo(JsonValueKind.Undefined));
        }

        [Test]
        public void TryParse_CommentsAndTrailingCommas()
        {
            const string json = "{\n // comment\n \"EmailPort\": 587, /* block */\n}";
            Assert.That(JsonSerializationHelper.TryParseNode(json).GetInt32("EmailPort"), Is.EqualTo(587));
            using var doc = JsonSerializationHelper.TryParseDocument(json);
            Assert.That(doc.RootElement.GetInt32("EmailPort"), Is.EqualTo(587));
        }

        [Test]
        public void TryParseElement_OutlivesDocument()
        {
            var elem = JsonSerializationHelper.TryParseElement("{\"a\":\"b\"}");
            GC.Collect();
            Assert.That(elem.GetString("a"), Is.EqualTo("b"));
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("{bad")]
        [TestCase("[1,2]")]
        [TestCase("\"string\"")]
        [TestCase("5")]
        public void ParseObjectOrNew_NotAnObject_NewEmpty(string json)
        {
            var obj = JsonSerializationHelper.ParseObjectOrNew(json);
            Assert.That(obj, Is.Not.Null);
            Assert.That(obj.Count, Is.EqualTo(0));
        }

        [Test]
        public void ParseObjectOrNew_Object()
        {
            Assert.That(JsonSerializationHelper.ParseObjectOrNew("{\"a\":1}").GetInt32("a"), Is.EqualTo(1));
        }

        [Test]
        public void TryParseNodeFromFile()
        {
            string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ipban_json_value_" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                Assert.That(JsonSerializationHelper.TryParseNodeFromFile(path), Is.Null, "missing file");
                System.IO.File.WriteAllText(path, "{\"EmailPort\":587}");
                Assert.That(JsonSerializationHelper.TryParseNodeFromFile(path).GetInt32("EmailPort"), Is.EqualTo(587));
                System.IO.File.WriteAllText(path, "{bad");
                Assert.That(JsonSerializationHelper.TryParseNodeFromFile(path), Is.Null, "invalid json");
            }
            finally
            {
                System.IO.File.Delete(path);
            }
            Assert.That(JsonSerializationHelper.TryParseNodeFromFile(null), Is.Null);
        }

        // ---------------------------------------------------------------------
        // compatibility with the previous JsonElement helpers
        // ---------------------------------------------------------------------

        [Test]
        public void PreviousHelperBehaviour_Preserved()
        {
            // same cases as IPBanExtensionMethodsHelpersTests.JsonElementHelpers_ParseValuesOrDefaults
            using var doc = JsonDocument.Parse("{\"name\":\"alice\",\"i\":\"42\",\"l\":\"99\",\"b\":\"true\",\"d\":\"2024-01-02T03:04:05Z\"}");
            var elem = doc.RootElement;
            Assert.That(elem.GetString("name"), Is.EqualTo("alice"));
            Assert.That(elem.GetInt32("i"), Is.EqualTo(42));
            Assert.That(elem.GetInt64("l"), Is.EqualTo(99L));
            Assert.That(elem.GetBool("b"), Is.True);
            Assert.That(elem.GetDateTime("d", DateTime.MinValue).ToUniversalTime(), Is.EqualTo(new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc)));
            Assert.That(elem.GetString("missing", "default"), Is.EqualTo("default"));
        }

        [Test]
        public void PreviousHelperBehaviour_Fixed()
        {
            var elem = Element();
            // negative numbers used to read as the default (NumberStyles.None)
            Assert.That(elem.GetInt32("negNum"), Is.EqualTo(-12));
            Assert.That(elem.GetInt64("negStr"), Is.EqualTo(-12L));
            // a number where a date was expected used to throw from TryGetDateTime
            Assert.That(elem.GetDateTime("intNum", DateTime.MinValue), Is.EqualTo(DateTime.MinValue));
            // json null used to read as an empty string
            Assert.That(elem.GetString("nullValue"), Is.Null);
        }

        // ---------------------------------------------------------------------
        // Utf8JsonReader helpers (custom converters)
        // ---------------------------------------------------------------------

        private static Utf8JsonReader ReaderOn(string json)
        {
            var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
            Assert.That(reader.Read(), Is.True);
            return reader;
        }

        [TestCase("\"abc\"", "abc")]
        [TestCase("587", "587")]
        [TestCase("-1.5e3", "-1.5e3")]
        [TestCase("true", "true")]
        [TestCase("false", "false")]
        [TestCase("null", "dflt")]
        [TestCase("{}", "dflt")]
        [TestCase("[]", "dflt")]
        public void Reader_GetStringValue_NeverThrows(string json, string expected)
        {
            var reader = ReaderOn(json);
            Assert.That(reader.GetStringValue("dflt"), Is.EqualTo(expected));
        }

        [TestCase("42", true, 42L)]
        [TestCase("\"42\"", true, 42L)]
        [TestCase("-7", true, -7L)]
        [TestCase("5.0", true, 5L)]
        [TestCase("1e3", true, 1000L)]
        [TestCase("1.5", false, 0L)]
        [TestCase("\"abc\"", false, 0L)]
        [TestCase("null", false, 0L)]
        [TestCase("true", false, 0L)]
        public void Reader_TryGetInt64Value_NeverThrows(string json, bool ok, long expected)
        {
            var reader = ReaderOn(json);
            Assert.That(reader.TryGetInt64Value(out long value), Is.EqualTo(ok));
            Assert.That(value, Is.EqualTo(expected));
        }

        [TestCase("1.25", true, 1.25)]
        [TestCase("\"1.25\"", true, 1.25)]
        [TestCase("\"x\"", false, 0.0)]
        [TestCase("null", false, 0.0)]
        public void Reader_TryGetDecimalValue_NeverThrows(string json, bool ok, double expected)
        {
            var reader = ReaderOn(json);
            Assert.That(reader.TryGetDecimalValue(out decimal value), Is.EqualTo(ok));
            Assert.That(value, Is.EqualTo((decimal)expected));
        }
    }
}
