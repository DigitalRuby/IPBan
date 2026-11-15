/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// compiled into projects with and without nullable reference types enabled
#nullable disable

#region Imports

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Safe json value access for <see cref="JsonElement"/> and <see cref="JsonNode"/>.
    /// </summary>
    /// <remarks>
    /// This file is self-contained (System.Text.Json only, no reflection) so projects that cannot reference IPBanCore,
    /// such as the native AOT Lockdown projects, compile it in through a linked Compile item.
    /// Never reference IPBanCore and one of those projects from the same project: both define these public types.
    /// These never throw for a missing property, a property of an unexpected json type, a json null,
    /// or calling them on something that is not an object or array; they return the default value instead.
    /// Values are converted leniently so a setting written as "587" or 587 reads the same:
    /// strings read as-is, numbers and booleans read as their json text ("587", "true", "false"),
    /// numeric strings read as numbers, "true"/"false"/1/0 read as booleans.
    /// Use these instead of JsonElement.GetString()/GetInt32()/GetProperty() or JsonNode.GetValue&lt;T&gt;()/indexers,
    /// which throw on any of the above. To parse json text safely see <see cref="JsonSerializationHelper.TryParseNode(string)"/>
    /// and <see cref="JsonSerializationHelper.TryParseDocument(string)"/>.
    /// </remarks>
    public static partial class ExtensionMethods
    {
        #region JsonElement navigation

        /// <summary>
        /// Try to get a property of a json object. Unlike <see cref="JsonElement.TryGetProperty(string, out JsonElement)"/>
        /// this returns false instead of throwing when the element is not an object.
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="value">Property value, or default if not found</param>
        /// <returns>True if found</returns>
        public static bool TryGetObjectProperty(this JsonElement elem, string name, out JsonElement value)
        {
            if (name is not null && elem.ValueKind == JsonValueKind.Object && elem.TryGetProperty(name, out value))
            {
                return true;
            }
            value = default;
            return false;
        }

        /// <summary>
        /// Get a property of a json object, or a default element (ValueKind Undefined) if not found or not an object.
        /// Safe to chain: elem.GetElement("a").GetElement("b").GetString("c").
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <returns>Property value or default</returns>
        public static JsonElement GetElement(this JsonElement elem, string name)
        {
            return elem.TryGetObjectProperty(name, out JsonElement value) ? value : default;
        }

        /// <summary>
        /// Get an item of a json array, or a default element (ValueKind Undefined) if out of range or not an array
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="index">Index</param>
        /// <returns>Item or default</returns>
        public static JsonElement GetElement(this JsonElement elem, int index)
        {
            if (elem.ValueKind == JsonValueKind.Array && index >= 0 && index < elem.GetArrayLength())
            {
                return elem[index];
            }
            return default;
        }

        /// <summary>
        /// Enumerate a json array, or nothing if the element is not an array
        /// </summary>
        /// <param name="elem">Element</param>
        /// <returns>Items</returns>
        public static IEnumerable<JsonElement> EnumerateArrayOrEmpty(this JsonElement elem)
        {
            return elem.ValueKind == JsonValueKind.Array ? elem.EnumerateArray() : Enumerable.Empty<JsonElement>();
        }

        /// <summary>
        /// Enumerate the properties of a json object, or nothing if the element is not an object
        /// </summary>
        /// <param name="elem">Element</param>
        /// <returns>Properties</returns>
        public static IEnumerable<JsonProperty> EnumerateObjectOrEmpty(this JsonElement elem)
        {
            return elem.ValueKind == JsonValueKind.Object ? elem.EnumerateObject() : Enumerable.Empty<JsonProperty>();
        }

        #endregion JsonElement navigation

        #region JsonElement property values

        /// <summary>
        /// Get a property as a string
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or json null</param>
        /// <returns>String value; numbers and booleans as their json text, objects and arrays as json</returns>
        public static string GetString(this JsonElement elem, string name, string defaultValue = null)
        {
            return elem.GetElement(name).GetStringValue(defaultValue);
        }

        /// <summary>
        /// Get a property as an int32 (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Int32</returns>
        public static int GetInt32(this JsonElement elem, string name, int defaultValue = 0)
        {
            return elem.GetElement(name).GetInt32Value(defaultValue);
        }

        /// <summary>
        /// Get a property as an int64 (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Int64</returns>
        public static long GetInt64(this JsonElement elem, string name, long defaultValue = 0)
        {
            return elem.GetElement(name).GetInt64Value(defaultValue);
        }

        /// <summary>
        /// Get a property as a double (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Double</returns>
        public static double GetDouble(this JsonElement elem, string name, double defaultValue = 0)
        {
            return elem.GetElement(name).GetDoubleValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a decimal (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Decimal</returns>
        public static decimal GetDecimal(this JsonElement elem, string name, decimal defaultValue = 0)
        {
            return elem.GetElement(name).GetDecimalValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a bool (true/false, "true"/"false" in any case, 1/0)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Bool</returns>
        public static bool GetBool(this JsonElement elem, string name, bool defaultValue = false)
        {
            return elem.GetElement(name).GetBoolValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a date time (iso 8601 or other invariant culture date string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>DateTime</returns>
        public static DateTime GetDateTime(this JsonElement elem, string name, DateTime defaultValue = default)
        {
            return elem.GetElement(name).GetDateTimeValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a guid
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Guid</returns>
        public static Guid GetGuid(this JsonElement elem, string name, Guid defaultValue = default)
        {
            return elem.GetElement(name).GetGuidValue(defaultValue);
        }

        /// <summary>
        /// Try to get a property as an enum value (name in any case, or number)
        /// </summary>
        /// <typeparam name="TEnum">Enum type</typeparam>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="value">Enum value</param>
        /// <returns>True if found and parsed</returns>
        public static bool TryGetEnum<TEnum>(this JsonElement elem, string name, out TEnum value) where TEnum : struct, Enum
        {
            return TryParseEnum(elem.GetString(name), out value);
        }

        #endregion JsonElement property values

        #region JsonElement values

        /// <summary>
        /// Get this element as a string
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if undefined or json null</param>
        /// <returns>String value; numbers and booleans as their json text, objects and arrays as json</returns>
        public static string GetStringValue(this JsonElement elem, string defaultValue = null)
        {
            return elem.ValueKind switch
            {
                JsonValueKind.String => elem.GetString(),
                JsonValueKind.Number or JsonValueKind.Object or JsonValueKind.Array => elem.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => defaultValue
            };
        }

        /// <summary>
        /// Get this element as an int32 (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Int32</returns>
        public static int GetInt32Value(this JsonElement elem, int defaultValue = 0)
        {
            return TryParseJsonInt64(elem.GetStringValue(), out long value) && value >= int.MinValue && value <= int.MaxValue ? (int)value : defaultValue;
        }

        /// <summary>
        /// Get this element as an int64 (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Int64</returns>
        public static long GetInt64Value(this JsonElement elem, long defaultValue = 0)
        {
            return TryParseJsonInt64(elem.GetStringValue(), out long value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this element as a double (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Double</returns>
        public static double GetDoubleValue(this JsonElement elem, double defaultValue = 0)
        {
            return TryParseJsonDouble(elem.GetStringValue(), out double value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this element as a decimal (number or numeric string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Decimal</returns>
        public static decimal GetDecimalValue(this JsonElement elem, decimal defaultValue = 0)
        {
            return TryParseJsonDecimal(elem.GetStringValue(), out decimal value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this element as a bool (true/false, "true"/"false" in any case, 1/0)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Bool</returns>
        public static bool GetBoolValue(this JsonElement elem, bool defaultValue = false)
        {
            return TryParseJsonBool(elem.GetStringValue(), out bool value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this element as a date time (iso 8601 or other invariant culture date string)
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>DateTime</returns>
        public static DateTime GetDateTimeValue(this JsonElement elem, DateTime defaultValue = default)
        {
            if (elem.ValueKind == JsonValueKind.String && elem.TryGetDateTime(out DateTime value))
            {
                return value;
            }
            return TryParseJsonDateTime(elem.GetStringValue(), out value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this element as a guid
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Guid</returns>
        public static Guid GetGuidValue(this JsonElement elem, Guid defaultValue = default)
        {
            return Guid.TryParse(elem.GetStringValue(), out Guid value) ? value : defaultValue;
        }

        #endregion JsonElement values

        #region JsonNode navigation

        /// <summary>
        /// Get a property of a json object. Unlike the JsonNode indexer this returns null instead of throwing
        /// when the node is null, an array or a value.
        /// Safe to chain: node.GetNode("a").GetNode("b").GetString("c").
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <returns>Property value or null</returns>
        public static JsonNode GetNode(this JsonNode node, string name)
        {
            return name is not null && node is JsonObject obj && obj.TryGetPropertyValue(name, out JsonNode value) ? value : null;
        }

        /// <summary>
        /// Get an item of a json array, or null if out of range or not an array
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="index">Index</param>
        /// <returns>Item or null</returns>
        public static JsonNode GetNode(this JsonNode node, int index)
        {
            return node is JsonArray array && index >= 0 && index < array.Count ? array[index] : null;
        }

        /// <summary>
        /// Enumerate a json array, or nothing if the node is not an array
        /// </summary>
        /// <param name="node">Node</param>
        /// <returns>Items</returns>
        public static IEnumerable<JsonNode> EnumerateArrayOrEmpty(this JsonNode node)
        {
            return node is JsonArray array ? array : Enumerable.Empty<JsonNode>();
        }

        /// <summary>
        /// Enumerate the properties of a json object, or nothing if the node is not an object
        /// </summary>
        /// <param name="node">Node</param>
        /// <returns>Properties</returns>
        public static IEnumerable<KeyValuePair<string, JsonNode>> EnumerateObjectOrEmpty(this JsonNode node)
        {
            return node is JsonObject obj ? obj : Enumerable.Empty<KeyValuePair<string, JsonNode>>();
        }

        #endregion JsonNode navigation

        #region JsonNode property values

        /// <summary>
        /// Get a property as a string
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or json null</param>
        /// <returns>String value; numbers and booleans as their json text, objects and arrays as json</returns>
        public static string GetString(this JsonNode node, string name, string defaultValue = null)
        {
            return node.GetNode(name).GetStringValue(defaultValue);
        }

        /// <summary>
        /// Get a property as an int32 (number or numeric string)
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Int32</returns>
        public static int GetInt32(this JsonNode node, string name, int defaultValue = 0)
        {
            return node.GetNode(name).GetInt32Value(defaultValue);
        }

        /// <summary>
        /// Get a property as an int64 (number or numeric string)
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Int64</returns>
        public static long GetInt64(this JsonNode node, string name, long defaultValue = 0)
        {
            return node.GetNode(name).GetInt64Value(defaultValue);
        }

        /// <summary>
        /// Get a property as a double (number or numeric string)
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Double</returns>
        public static double GetDouble(this JsonNode node, string name, double defaultValue = 0)
        {
            return node.GetNode(name).GetDoubleValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a decimal (number or numeric string)
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Decimal</returns>
        public static decimal GetDecimal(this JsonNode node, string name, decimal defaultValue = 0)
        {
            return node.GetNode(name).GetDecimalValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a bool (true/false, "true"/"false" in any case, 1/0)
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Bool</returns>
        public static bool GetBool(this JsonNode node, string name, bool defaultValue = false)
        {
            return node.GetNode(name).GetBoolValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a date time (iso 8601 or other invariant culture date string)
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>DateTime</returns>
        public static DateTime GetDateTime(this JsonNode node, string name, DateTime defaultValue = default)
        {
            return node.GetNode(name).GetDateTimeValue(defaultValue);
        }

        /// <summary>
        /// Get a property as a guid
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found or not convertible</param>
        /// <returns>Guid</returns>
        public static Guid GetGuid(this JsonNode node, string name, Guid defaultValue = default)
        {
            return node.GetNode(name).GetGuidValue(defaultValue);
        }

        /// <summary>
        /// Try to get a property as an enum value (name in any case, or number)
        /// </summary>
        /// <typeparam name="TEnum">Enum type</typeparam>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="value">Enum value</param>
        /// <returns>True if found and parsed</returns>
        public static bool TryGetEnum<TEnum>(this JsonNode node, string name, out TEnum value) where TEnum : struct, Enum
        {
            return TryParseEnum(node.GetString(name), out value);
        }

        #endregion JsonNode property values

        #region JsonNode values

        /// <summary>
        /// Get this node as a string
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if null</param>
        /// <returns>String value; numbers and booleans as their json text, objects and arrays as json</returns>
        public static string GetStringValue(this JsonNode node, string defaultValue = null)
        {
            switch (node)
            {
                case null:
                    return defaultValue;

                case JsonValue value:
                    if (value.TryGetValue(out JsonElement elem))
                    {
                        // parsed from json text
                        return elem.GetStringValue(defaultValue);
                    }
                    if (value.TryGetValue(out string text))
                    {
                        return text;
                    }
                    if (value.TryGetValue(out bool boolValue))
                    {
                        return boolValue ? "true" : "false";
                    }
                    if (value.TryGetValue(out char charValue))
                    {
                        return charValue.ToString();
                    }

                    // created in code from a number, date, guid, etc.
                    string json = value.ToJsonString();
                    if (json.Length >= 2 && json[0] == '"')
                    {
                        using JsonDocument doc = JsonDocument.Parse(json);
                        return doc.RootElement.GetString();
                    }
                    return json == "null" ? defaultValue : json;

                default:
                    // object or array
                    return node.ToJsonString();
            }
        }

        /// <summary>
        /// Get this node as an int32 (number or numeric string)
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Int32</returns>
        public static int GetInt32Value(this JsonNode node, int defaultValue = 0)
        {
            return TryParseJsonInt64(node.GetStringValue(), out long value) && value >= int.MinValue && value <= int.MaxValue ? (int)value : defaultValue;
        }

        /// <summary>
        /// Get this node as an int64 (number or numeric string)
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Int64</returns>
        public static long GetInt64Value(this JsonNode node, long defaultValue = 0)
        {
            return TryParseJsonInt64(node.GetStringValue(), out long value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this node as a double (number or numeric string)
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Double</returns>
        public static double GetDoubleValue(this JsonNode node, double defaultValue = 0)
        {
            return TryParseJsonDouble(node.GetStringValue(), out double value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this node as a decimal (number or numeric string)
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Decimal</returns>
        public static decimal GetDecimalValue(this JsonNode node, decimal defaultValue = 0)
        {
            return TryParseJsonDecimal(node.GetStringValue(), out decimal value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this node as a bool (true/false, "true"/"false" in any case, 1/0)
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Bool</returns>
        public static bool GetBoolValue(this JsonNode node, bool defaultValue = false)
        {
            return TryParseJsonBool(node.GetStringValue(), out bool value) ? value : defaultValue;
        }

        /// <summary>
        /// Get this node as a date time (iso 8601 or other invariant culture date string)
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>DateTime</returns>
        public static DateTime GetDateTimeValue(this JsonNode node, DateTime defaultValue = default)
        {
            if (node is JsonValue value)
            {
                if (value.TryGetValue(out JsonElement elem))
                {
                    return elem.GetDateTimeValue(defaultValue);
                }
                if (value.TryGetValue(out DateTime dateTime))
                {
                    return dateTime;
                }
            }
            return TryParseJsonDateTime(node.GetStringValue(), out DateTime parsed) ? parsed : defaultValue;
        }

        /// <summary>
        /// Get this node as a guid
        /// </summary>
        /// <param name="node">Node, may be null</param>
        /// <param name="defaultValue">Default if not convertible</param>
        /// <returns>Guid</returns>
        public static Guid GetGuidValue(this JsonNode node, Guid defaultValue = default)
        {
            return Guid.TryParse(node.GetStringValue(), out Guid value) ? value : defaultValue;
        }

        #endregion JsonNode values

        #region JsonNode writes

        /// <summary>
        /// Set a property on a json object. Unlike the JsonNode indexer this returns false instead of throwing
        /// when the node is null, an array or a value, and it never throws for a value that already has a parent
        /// (the value is copied).
        /// </summary>
        /// <param name="node">Node</param>
        /// <param name="name">Property name</param>
        /// <param name="value">Value, null for json null</param>
        /// <returns>True if set</returns>
        public static bool TrySetProperty(this JsonNode node, string name, JsonNode value)
        {
            if (name is null || node is not JsonObject obj)
            {
                return false;
            }
            obj[name] = value?.Parent is null ? value : value.DeepClone();
            return true;
        }

        /// <summary>
        /// Get a child json object, adding a new empty one if it is missing or is not an object
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Property name</param>
        /// <returns>Child object</returns>
        public static JsonObject GetOrAddObject(this JsonObject obj, string name)
        {
            ArgumentNullException.ThrowIfNull(obj);
            ArgumentNullException.ThrowIfNull(name);
            if (obj[name] is JsonObject child)
            {
                return child;
            }
            child = new JsonObject();
            obj[name] = child;
            return child;
        }

        /// <summary>
        /// Get a child json array, adding a new empty one if it is missing or is not an array
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Property name</param>
        /// <returns>Child array</returns>
        public static JsonArray GetOrAddArray(this JsonObject obj, string name)
        {
            ArgumentNullException.ThrowIfNull(obj);
            ArgumentNullException.ThrowIfNull(name);
            if (obj[name] is JsonArray child)
            {
                return child;
            }
            child = new JsonArray();
            obj[name] = child;
            return child;
        }

        #endregion JsonNode writes

        #region Utf8JsonReader reads (for custom converters)

        /// <summary>
        /// Get the current reader token as a string without throwing
        /// </summary>
        /// <param name="reader">Reader positioned on a value token</param>
        /// <param name="defaultValue">Default for null, objects, arrays or anything else</param>
        /// <returns>String value; numbers as their json text, booleans as "true" / "false"</returns>
        public static string GetStringValue(ref this Utf8JsonReader reader, string defaultValue = null)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.String:
                case JsonTokenType.PropertyName:
                    return reader.GetString();
                case JsonTokenType.Number:
                    return reader.HasValueSequence
                        ? Encoding.UTF8.GetString(System.Buffers.BuffersExtensions.ToArray(reader.ValueSequence))
                        : Encoding.UTF8.GetString(reader.ValueSpan);
                case JsonTokenType.True:
                    return "true";
                case JsonTokenType.False:
                    return "false";
                default:
                    return defaultValue;
            }
        }

        /// <summary>
        /// Get the current reader token as an int64 (number or numeric string) without throwing
        /// </summary>
        /// <param name="reader">Reader positioned on a value token</param>
        /// <param name="value">Receives the value</param>
        /// <returns>True if the token converted, false otherwise</returns>
        public static bool TryGetInt64Value(ref this Utf8JsonReader reader, out long value)
        {
            if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt64(out value))
            {
                return true;
            }
            return TryParseJsonInt64(reader.GetStringValue(), out value);
        }

        /// <summary>
        /// Get the current reader token as a decimal (number or numeric string) without throwing
        /// </summary>
        /// <param name="reader">Reader positioned on a value token</param>
        /// <param name="value">Receives the value</param>
        /// <returns>True if the token converted, false otherwise</returns>
        public static bool TryGetDecimalValue(ref this Utf8JsonReader reader, out decimal value)
        {
            if (reader.TokenType == JsonTokenType.Number && reader.TryGetDecimal(out value))
            {
                return true;
            }
            return TryParseJsonDecimal(reader.GetStringValue(), out value);
        }

        #endregion Utf8JsonReader reads (for custom converters)

        #region Json value parsing

        private static bool TryParseJsonInt64(string text, out long value)
        {
            if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            {
                return true;
            }

            // 5.0, 1e3, etc.
            if (decimal.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out decimal number) &&
                number == decimal.Truncate(number) && number >= long.MinValue && number <= long.MaxValue)
            {
                value = (long)number;
                return true;
            }
            value = 0;
            return false;
        }

        private static bool TryParseJsonDouble(string text, out double value)
        {
            return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
        }

        private static bool TryParseJsonDecimal(string text, out decimal value)
        {
            return decimal.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
        }

        private static bool TryParseJsonBool(string text, out bool value)
        {
            if (bool.TryParse(text, out value))
            {
                return true;
            }
            if (TryParseJsonInt64(text, out long number) && (number == 0 || number == 1))
            {
                value = number == 1;
                return true;
            }
            value = false;
            return false;
        }

        private static bool TryParseJsonDateTime(string text, out DateTime value)
        {
            return DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value);
        }

        private static bool TryParseEnum<TEnum>(string text, out TEnum value) where TEnum : struct, Enum
        {
            if (!string.IsNullOrWhiteSpace(text) && Enum.TryParse(text.Trim(), true, out value))
            {
                return true;
            }
            value = default;
            return false;
        }

        #endregion Json value parsing
    }

    /// <summary>
    /// Safe json parsing: never throws for null, empty or invalid json text.
    /// </summary>
    public static partial class JsonSerializationHelper
    {
        /// <summary>
        /// Lenient parse options for safe parsing: comments are skipped and trailing commas are allowed,
        /// matching what people hand-edit into config files.
        /// </summary>
        private static readonly JsonDocumentOptions safeDocumentOptions = new()
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        };

        /// <summary>
        /// Parse json text into a node without throwing
        /// </summary>
        /// <param name="json">Json text, may be null or empty</param>
        /// <returns>Node, or null if the text is null, empty, invalid json or the json literal null</returns>
        public static JsonNode TryParseNode(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }
            try
            {
                return JsonNode.Parse(json, documentOptions: safeDocumentOptions);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        /// <summary>
        /// Parse a json file into a node without throwing
        /// </summary>
        /// <param name="path">File path</param>
        /// <returns>Node, or null if the file is missing, unreadable or not valid json</returns>
        public static JsonNode TryParseNodeFromFile(string path)
        {
            try
            {
                return File.Exists(path) ? TryParseNode(File.ReadAllText(path, Encoding.UTF8)) : null;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }

        /// <summary>
        /// Parse json text into a json object without throwing, for read-modify-write of json strings such as props columns
        /// </summary>
        /// <param name="json">Json text, may be null or empty</param>
        /// <returns>The parsed object, or a new empty object if the text is null, empty, invalid or not a json object</returns>
        public static JsonObject ParseObjectOrNew(string json)
        {
            return TryParseNode(json) as JsonObject ?? new JsonObject();
        }

        /// <summary>
        /// Parse json text into a document without throwing. Dispose the result.
        /// </summary>
        /// <param name="json">Json text, may be null or empty</param>
        /// <returns>Document, or null if the text is null, empty or invalid json</returns>
        public static JsonDocument TryParseDocument(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }
            try
            {
                return JsonDocument.Parse(json, safeDocumentOptions);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        /// <summary>
        /// Parse json text and return a copy of the root element without throwing. The element does not need disposing.
        /// </summary>
        /// <param name="json">Json text, may be null or empty</param>
        /// <returns>Root element, or a default element (ValueKind Undefined) if the text is null, empty or invalid json</returns>
        public static JsonElement TryParseElement(string json)
        {
            using JsonDocument doc = TryParseDocument(json);
            return doc is null ? default : doc.RootElement.Clone();
        }
    }
}
