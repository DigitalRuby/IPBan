/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

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

#region Imports

using Newtonsoft.Json;

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Serialization;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Info about a single Windows event viewer lookup
    /// </summary>
    public class EventViewerExpression
    {
        /// <summary>
        /// The regex, created from Regex property
        /// </summary>
        [XmlIgnore]
        public Regex RegexObject { get; private set; }

        private string xpath;
        /// <summary>
        /// Xpath to find
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.XPath))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string XPath
        {
            get => xpath;
            set
            {
                xpath = value;
                XPathIsOptional = (xpath != null && xpath == "//Data[@Name='ProcessName']");
            }
        }

        private string regex = string.Empty;
        /// <summary>
        /// Regex string
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.XPathRegex))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public XmlCData Regex
        {
            get => regex;
            set => RegexObject = IPBanConfig.ParseRegex(regex = value);
        }

        /// <summary>
        /// Whether the xpath is optional
        /// </summary>
        [JsonIgnore]
        [XmlIgnore]
        public bool XPathIsOptional { get; private set; }
    }

    /// <summary>
    /// A single Windows event viewer group
    /// </summary>
    [XmlRoot("Group")]
    public class EventViewerExpressionGroup
    {
        /// <summary>
        /// The event viewer source
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.Source))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Source { get; set; } = string.Empty;

        /// <summary>
        /// Keywords as a ULONG
        /// </summary>
        [XmlIgnore]
        public ulong KeywordsULONG { get; private set; }

        /// <summary>
        /// Minimum Windows major version - see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        /// </summary>
        public int MinimumWindowsMajorVersion { get; set; } = 6;

        /// <summary>
        /// Minimum Windows minor version - see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        /// </summary>
        public int MinimumWindowsMinorVersion { get; set; }

        /// <summary>
        /// Set automatically, determines whether this expression is failed login (false) or successful login (true)
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.NotifyOnly))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public bool NotifyOnly { get; set; }

        /// <summary>
        /// Keywords backing variable, private
        /// </summary>
        private string keywords;

        /// <summary>
        /// Keywords as HEX string
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.EventViewerKeywords))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Keywords
        {
            get => keywords;
            set
            {
                keywords = value;

                // parse, removing any 0x prefix
                if (value.StartsWith("0x"))
                {
                    value = value[2..];
                }
                KeywordsULONG = ulong.Parse(value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            }
        }

        public void AppendQueryString(StringBuilder builder, int id = 1)
        {
            ulong keywordsDecimal = ulong.Parse(Keywords[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            builder.Append("<Query Id='");
            builder.Append(id.ToStringInvariant());
            builder.Append("' Path='");
            builder.Append(Path);
            builder.Append("'><Select Path='");
            builder.Append(Path);
            builder.Append("'>*[System[(band(Keywords,");
            builder.Append(keywordsDecimal.ToStringInvariant());
            builder.Append("))]]</Select></Query>");
        }

        public void SetExpressionsFromExpressionsText()
        {
            if (ExpressionsText is null)
            {
                return;
            }

            Expressions.Clear();
            string[] lines = IPBanConfig.CleanMultilineString(ExpressionsText).Split('\n');
            string line;
            EventViewerExpression currentExpression = null;
            for (int i = 0; i < lines.Length; i++)
            {
                line = lines[i].Trim();
                if (line.StartsWith("//") || line.StartsWith("(//"))
                {
                    if (currentExpression != null)
                    {
                        Expressions.Add(currentExpression);
                    }
                    currentExpression = new EventViewerExpression { XPath = line, Regex = string.Empty };
                }
                else if (line.Length != 0 && currentExpression != null)
                {
                    currentExpression.Regex += line + "\n";
                }
            }
            if (currentExpression != null)
            {
                Expressions.Add(currentExpression);
            }
        }

        /// <summary>
        /// Path to the event viewer entry, i.e. Application or Security
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.EventViewerPath))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Path { get; set; } = string.Empty;

        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.EventViewerExpressions))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        [XmlArray("Expressions")]
        [XmlArrayItem("Expression")]
        public List<EventViewerExpression> Expressions { get; set; } = new List<EventViewerExpression>();

        /// <summary>
        /// If using plain text expressions, this will be set and needs conversion. Leave null if you are using Expressions directly.
        /// The format is xpath (//*), newline, and then regex, newline, repeated.
        /// </summary>
        [XmlIgnore]
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.EventViewerExpressions))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string ExpressionsText { get; set; }

        /// <summary>
        /// Override failed login threshold or 0 for default
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.FailedLoginThreshold))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public int FailedLoginThreshold { get; set; }

        /// <summary>
        /// Log level for event
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.LogLevel))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public LogLevel LogLevel { get; set; } = LogLevel.Warning;
    }

    /// <summary>
    /// Base class for event viewer expressions
    /// </summary>
    public class EventViewerExpressions
    {
        [XmlArray("Groups")]
        [XmlArrayItem("Group")]
        public List<EventViewerExpressionGroup> Groups { get; set; } = new List<EventViewerExpressionGroup>();
    }

    /// <summary>
    /// List of Windows event viewer groups for failed login attempts
    /// </summary>
    [XmlType("ExpressionsToBlock")]
    public class EventViewerExpressionsToBlock : EventViewerExpressions { }

    /// <summary>
    /// List of Windows event viewer groups for success login attempts
    /// </summary>
    [XmlType("ExpressionsToNotify")]
    public class EventViewerExpressionsToNotify : EventViewerExpressions { }
}
