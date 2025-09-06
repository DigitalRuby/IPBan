using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// More compact guids for system.text.json
/// </summary>
public class JsonGuidConverter : JsonConverter<Guid>
{
    /// <inheritdoc />
    public override Guid Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string s = reader.GetString();
        Span<byte> guidBytes = stackalloc byte[16];
        if (string.IsNullOrWhiteSpace(s) ||
            !Convert.TryFromBase64String(s, guidBytes, out int bytesWritten) ||
            bytesWritten != 16)
        {
            if (Guid.TryParse(s, out Guid guid))
            {
                return guid;
            }
            return Guid.Empty;
        }
        return new Guid(guidBytes);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, Guid value, JsonSerializerOptions options)
    {
        Span<byte> guidBytes = stackalloc byte[16];
        _ = value.TryWriteBytes(guidBytes);
        writer.WriteBase64StringValue(guidBytes);
    }
}
