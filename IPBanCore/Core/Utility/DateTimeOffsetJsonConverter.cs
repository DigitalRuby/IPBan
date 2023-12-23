using System;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// DateTimeOffset converter
    /// </summary>
    public sealed class DateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
    {
        /// <inheritdoc />
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            return DateTimeOffset.Parse(reader.GetString() ?? string.Empty, CultureInfo.InvariantCulture);
        }

        /// <inheritdoc />
        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString("s") + "Z");
        }
    }
}
