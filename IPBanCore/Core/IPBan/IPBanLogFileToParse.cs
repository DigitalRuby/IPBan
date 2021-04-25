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

using Newtonsoft.Json;

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Xml.Serialization;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Log file to parse data
    /// </summary>
    [XmlRoot("LogFile")]
    public class IPBanLogFileToParse
    {
        /// <summary>
        /// Source
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.Source))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Source { get; set; } = string.Empty;

        /// <summary>
        /// Path and mask, one per line
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.PathAndMask))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string PathAndMask { get; set; } = string.Empty;

        /// <summary>
        /// Failed login regex
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.FailedLoginRegex))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public XmlCData FailedLoginRegex { get; set; } = string.Empty;

        /// <summary>
        /// Failed login timestamp format
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.FailedLoginRegexTimestampFormat))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string FailedLoginRegexTimestampFormat { get; set; } = string.Empty;

        /// <summary>
        /// Failed login log level
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.FailedLoginLogLevel))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public LogLevel FailedLoginLogLevel { get; set; } = LogLevel.Warning;

        /// <summary>
        /// Successful login regex
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.SuccessfulLoginRegex))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public XmlCData SuccessfulLoginRegex { get; set; } = string.Empty;

        /// <summary>
        /// Successful login timestamp format
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.SuccessfulLoginRegexTimestampFormat))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string SuccessfulLoginRegexTimestampFormat { get; set; } = string.Empty;

        /// <summary>
        /// Successful login log level
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.SuccessfulLoginLogLevel))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public LogLevel SuccessfulLoginLogLevel { get; set; } = LogLevel.Warning;

        /// <summary>
        /// Platform regex, i.e. Windows, Linux, etc.
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.PlatformRegex))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public XmlCData PlatformRegex { get; set; } = string.Empty;

        /// <summary>
        /// How often in milliseconds to ping the file
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.LogFilePingInterval))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public int PingInterval { get; set; } = 10000;

        /// <summary>
        /// Max file size in bytes
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.MaxFileSize))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public int MaxFileSize { get; set; }

        /// <summary>
        /// Override failed login threshold or 0 for default
        /// </summary>
        [DisplayFormat(ConvertEmptyStringToNull = false)]
        [Required(AllowEmptyStrings = true)]
        [LocalizedDisplayName(nameof(IPBanResources.FailedLoginThreshold))]
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public int FailedLoginThreshold { get; set; }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return string.Format("Path/mask: {0}, platform: {1}", PathAndMask, PlatformRegex);
        }

        /// <summary>
        /// Get an array of each individual path/mask, converted to normalized glob syntax
        /// </summary>
        public string[] PathsAndMasks
        {
            get
            {
                List<string> list = new();
                foreach (string s in PathAndMask.Split('\n'))
                {
                    if (!string.IsNullOrWhiteSpace(s))
                    {
                        list.Add(LogFileScanner.NormalizeGlob(s, out _, out _));
                    }
                }
                return list.ToArray();
            }
        }
    }

    /// <summary>
    /// Log files to parse
    /// </summary>
    [XmlType("LogFilesToParse")]
    public class IPBanLogFilesToParse
    {
        /// <summary>
        /// Log files
        /// </summary>
        [XmlArray("LogFiles")]
        [XmlArrayItem("LogFile")]
        public IPBanLogFileToParse[] LogFiles;
    }
}
