using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Json serialization helper
/// </summary>
public static class JsonSerializationHelper
{
    private static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    /// <summary>
    /// Deserialize
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="json">Json text</param>
    /// <returns>Object</returns>
    public static T Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options)!;

    /// <summary>
    /// Serialize
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="obj">Object</param>
    /// <returns>Json text</returns>
    public static string Serialize<T>(T obj) => JsonSerializer.Serialize(obj, Options);

    /// <summary>
    /// Deserialize from stream
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="stream">Stream</param>
    /// <returns>Object</returns>
    /// <exception cref="ArgumentNullException">Stream is null</exception>
    public static T Deserialize<T>(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return JsonSerializer.Deserialize<T>(stream, Options)!;
    }

    /// <summary>
    /// Serialize
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="obj">Object</param>
    /// <param name="stream">Stream</param>
    /// <exception cref="ArgumentNullException">Stream is null</exception>
    public static void Serialize<T>(T obj, Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        JsonSerializer.Serialize(stream, obj, Options);
    }

    /// <summary>
    /// Deserialize async
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="stream">Stream</param>
    /// <param name="cancel">Cancel token</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">Stream is null</exception>
    public static async Task<T> DeserializeAsync<T>(Stream stream, CancellationToken cancel = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var rs = await JsonSerializer.DeserializeAsync<T>(stream, Options, cancel).ConfigureAwait(false);
        return rs!;
    }

    /// <summary>
    /// Serialize 
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="obj">Object</param>
    /// <param name="stream">Stream</param>
    /// <param name="cancel">Cancel token</param>
    /// <returns>Task</returns>
    /// <exception cref="ArgumentNullException">Stream is null</exception>
    public static Task SerializeAsync<T>(T obj, Stream stream, CancellationToken cancel = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return JsonSerializer.SerializeAsync(stream, obj, Options, cancel);
    }

    /// <summary>
    /// Deserialize from file
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="path">File path</param>
    /// <returns>Object</returns>
    public static T DeserializeFromFile<T>(string path)
    {
        using var fs = File.OpenRead(path);
        return Deserialize<T>(fs);
    }

    /// <summary>
    /// Serialize to file
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="obj">Object</param>
    /// <param name="path">Path</param>
    public static void SerializeToFile<T>(T obj, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var fs = File.Create(path);
        Serialize(obj, fs);
    }

    /// <summary>
    /// Deserialize from file async
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="path">Path</param>
    /// <param name="cancel">Cancel token</param>
    /// <returns>Object</returns>
    public static async Task<T> DeserializeFromFileAsync<T>(string path, CancellationToken cancel = default)
    {
        await using var fs = File.OpenRead(path);
        return await DeserializeAsync<T>(fs, cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// Serialize to file async
    /// </summary>
    /// <typeparam name="T">Type</typeparam>
    /// <param name="obj">Object</param>
    /// <param name="path">Path</param>
    /// <param name="cancel">Cancel token</param>
    /// <returns></returns>
    public static async Task SerializeToFileAsync<T>(T obj, string path, CancellationToken cancel = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        await using var fs = File.Create(path);
        await SerializeAsync(obj, fs, cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// Normalize json by sorting object properties and removing whitespace.
    /// </summary>
    /// <param name="json">JSON</param>
    /// <returns>JSON</returns>
    public static string Canonicalize(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder(json.Length);
        WriteCanonical(doc.RootElement, sb);
        return sb.ToString();
    }

    private static void WriteCanonical(JsonElement elem, StringBuilder sb)
    {
        switch (elem.ValueKind)
        {
            case JsonValueKind.Object:
                sb.Append('{');
                bool firstProp = true;
                foreach (var prop in elem.EnumerateObject().OrderBy(p => p.Name, System.StringComparer.Ordinal))
                {
                    if (!firstProp) sb.Append(',');
                    firstProp = false;
                    sb.Append('"').Append(Escape(prop.Name)).Append('"').Append(':');
                    WriteCanonical(prop.Value, sb);
                }
                sb.Append('}');
                break;
            case JsonValueKind.Array:
                sb.Append('[');
                bool first = true;
                foreach (var v in elem.EnumerateArray())
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteCanonical(v, sb);
                }
                sb.Append(']');
                break;
            case JsonValueKind.String:
                sb.Append('"').Append(Escape(elem.GetString()!)).Append('"');
                break;
            case JsonValueKind.Number:
                sb.Append(elem.GetRawText());
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                sb.Append(elem.GetRawText());
                break;
            default:
                sb.Append(elem.GetRawText());
                break;
        }
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
