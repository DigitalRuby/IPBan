using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Converts simple enums to/from lowercase, hyphenated strings, with a small special-case map
/// (e.g., enum member named "new_" serializes to "new" and deserializes back).
/// </summary>
internal sealed class JsonStringEnumLowercaseConverter : JsonConverterFactory
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert) => typeToConvert.IsEnum;

    /// <inheritdoc />
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        var convType = typeof(LowercaseEnumConverter<>).MakeGenericType(typeToConvert);
        return (JsonConverter)Activator.CreateInstance(convType)!;
    }

    private sealed class LowercaseEnumConverter<T> : JsonConverter<T> where T : struct, Enum
    {
        private static readonly Dictionary<string, T> ReadMap = BuildReadMap();
        private static readonly Dictionary<T, string> WriteMap = BuildWriteMap();

        private static Dictionary<string, T> BuildReadMap()
        {
            var map = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in Enum.GetNames<T>())
            {
                var value = Enum.Parse<T>(name);
                // canonical json token: lowercase + hyphens
                var jsonToken = name.ToLowerInvariant().Replace('_', '-');
                map[jsonToken] = value;
                // also accept raw lowercase and underscore form
                map[name.ToLowerInvariant()] = value;
            }
            // special token: "new" -> enum member "new_" (if present)
            if (Enum.GetNames<T>().Any(n => n.Equals("new_", StringComparison.Ordinal)))
            {
                var val = Enum.Parse<T>("new_");
                map["new"] = val;
            }
            return map;
        }

        private static Dictionary<T, string> BuildWriteMap()
        {
            var map = new Dictionary<T, string>();
            foreach (var name in Enum.GetNames<T>())
            {
                var value = Enum.Parse<T>(name);
                var token = name.ToLowerInvariant().Replace('_', '-');

                // special case: "new_" -> "new"
                if (name.Equals("new_", StringComparison.Ordinal))
                {
                    token = "new";
                }
                map[value] = token;
            }
            return map;
        }

        /// <inheritdoc />
        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                var raw = reader.GetString()!;

                // normalize commas/whitespace if a flags value accidentally routed here
                var key = raw.Trim();
                if (ReadMap.TryGetValue(key, out var val))
                {
                    return val;
                }
                // try underscore variant
                key = key.Replace('-', '_');
                if (Enum.TryParse<T>(key, true, out var parsed))
                {
                    return parsed;
                }
                throw new JsonException($"Invalid enum token '{raw}' for {typeof(T).Name}");
            }
            if (reader.TokenType == JsonTokenType.Number && reader.TryGetUInt64(out var num))
            {
                return (T)Enum.ToObject(typeof(T), num);
            }
            throw new JsonException($"Unexpected token {reader.TokenType} for enum {typeof(T).Name}");
        }

        /// <inheritdoc />
        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
        {
            if (WriteMap.TryGetValue(value, out var token))
            {
                writer.WriteStringValue(token);
                return;
            }

            // fallback to hyphenated lowercase name
            var name = value.ToString()!.ToLowerInvariant().Replace('_', '-');
            if (name == "new_") name = "new";
            writer.WriteStringValue(name);
        }
    }
}

/// <summary>
/// Converts [Flags] enums to/from a JSON array of lowercase, hyphenated strings.
/// Accepts legacy string formats ("a,b,c"), a single string token, or a numeric value.
/// Writes an empty array for zero.
/// Special-cases enum member named "new_" to serialize as "new".
/// </summary>
internal sealed class JsonStringEnumFlagsLowercaseConverter : JsonConverterFactory
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert) => typeToConvert.IsEnum;

    /// <inheritdoc />
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        var convType = typeof(FlagsLowercaseEnumConverter<>).MakeGenericType(typeToConvert);
        return (JsonConverter)Activator.CreateInstance(convType)!;
    }

    private sealed class FlagsLowercaseEnumConverter<T> : JsonConverter<T> where T : struct, Enum
    {
        private static readonly Dictionary<string, T> TokenToValue = BuildReadMap();
        private static readonly (T Value, string Token)[] ValueTokens = BuildWriteList();

        private static Dictionary<string, T> BuildReadMap()
        {
            var map = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in Enum.GetNames<T>())
            {
                var value = Enum.Parse<T>(name);
                var token = name.ToLowerInvariant().Replace('_', '-');
                if (name.Equals("new_", StringComparison.Ordinal)) token = "new";
                map[token] = value;
                map[name.ToLowerInvariant()] = value; // also accept underscores
            }

            // legacy literal for zero
            map["none"] = (T)Enum.ToObject(typeof(T), 0UL);
            return map;
        }

        private static (T, string)[] BuildWriteList()
        {
            var list = new List<(T, string)>();
            foreach (var name in Enum.GetNames<T>())
            {
                var value = Enum.Parse<T>(name);
                if (Convert.ToUInt64(value) == 0) continue; // skip zero
                var token = name.ToLowerInvariant().Replace('_', '-');
                if (name.Equals("new_", StringComparison.Ordinal)) token = "new";
                list.Add((value, token));
            }
            // deterministically order by token
            return list.OrderBy(t => t.Item2, StringComparer.Ordinal).ToArray();
        }

        /// <inheritdoc />
        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            ulong total = 0;

            if (reader.TokenType == JsonTokenType.StartArray)
            {
                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndArray) break;
                    if (reader.TokenType != JsonTokenType.String)
                        throw new JsonException($"Expected string in {typeof(T).Name} array");
                    var s = reader.GetString()!.Trim();
                    if (string.IsNullOrEmpty(s)) continue;
                    if (TokenToValue.TryGetValue(s, out var val))
                    {
                        total |= Convert.ToUInt64(val);
                    }
                    else
                    {
                        // try underscore variant
                        var normalized = s.Replace('-', '_');
                        if (Enum.TryParse<T>(normalized, true, out var parsed))
                        {
                            total |= Convert.ToUInt64(parsed);
                        }
                        else
                        {
                            throw new JsonException($"Invalid flag '{s}' for {typeof(T).Name}");
                        }
                    }
                }
                return (T)Enum.ToObject(typeof(T), total);
            }

            if (reader.TokenType == JsonTokenType.String)
            {
                var raw = reader.GetString()!.Trim();
                if (raw.Length == 0) return (T)Enum.ToObject(typeof(T), 0UL);
                // allow comma-separated legacy string
                foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (TokenToValue.TryGetValue(part, out var val))
                        total |= Convert.ToUInt64(val);
                    else
                    {
                        var normalized = part.Replace('-', '_');
                        if (Enum.TryParse<T>(normalized, true, out var parsed))
                            total |= Convert.ToUInt64(parsed);
                        else
                            throw new JsonException($"Invalid flag '{part}' for {typeof(T).Name}");
                    }
                }
                return (T)Enum.ToObject(typeof(T), total);
            }

            if (reader.TokenType == JsonTokenType.Number && reader.TryGetUInt64(out var num))
            {
                return (T)Enum.ToObject(typeof(T), num);
            }

            throw new JsonException($"Unexpected token {reader.TokenType} for flags enum {typeof(T).Name}");
        }

        /// <inheritdoc />
        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
        {
            ulong raw = Convert.ToUInt64(value);
            writer.WriteStartArray();
            if (raw != 0)
            {
                foreach (var (flag, token) in ValueTokens)
                {
                    if (value.HasFlag(flag))
                    {
                        writer.WriteStringValue(token);
                    }
                }
            }
            writer.WriteEndArray();
        }
    }
}