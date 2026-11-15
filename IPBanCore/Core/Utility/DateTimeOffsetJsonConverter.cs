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
            // json null, empty strings and unparseable values read as default rather than throwing
            return DateTimeOffset.TryParse(reader.GetStringValue(), CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset value)
                ? value
                : default;
        }

        /// <inheritdoc />
        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString("s") + "Z");
        }
    }
}
