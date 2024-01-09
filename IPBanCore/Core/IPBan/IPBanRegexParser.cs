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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Extract things out of text using regex
    /// </summary>
    public static class IPBanRegexParser
    {
        private static readonly Dictionary<string, Regex> regexCacheCompiled = [];
        private static readonly Dictionary<string, Regex> regexCacheNotCompiled = [];
        private static readonly char[] regexTrimChars =
[
            ',', ';', '|', '_', '-', '/', '\'', '\"', '(', ')', '[', ']', '{', '}', ' ', '\t', '\r', '\n'
        ];

        /// <summary>
        /// Allow truncating user names at any of these chars or empty array for no truncation
        /// </summary>
        private static char[] truncateUserNameCharsArray = [];

        /// <summary>
        /// Truncate user name chars value
        /// </summary>
        public static string TruncateUserNameChars
        {
            get => new(truncateUserNameCharsArray);
            set => truncateUserNameCharsArray = value?.ToCharArray() ?? [];
        }

        /// <summary>
        /// Get a regex from text
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="multiline">Whether to use multi-line regex, default is false which is single line</param>
        /// <returns>Regex or null if text is null or whitespace</returns>
        public static Regex ParseRegex(string text, bool multiline = false)
        {
            const int maxCacheSize = 200;

            text = (text ?? string.Empty).Trim();
            if (text.Length == 0)
            {
                return null;
            }

            string[] lines = text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            StringBuilder sb = new();
            foreach (string line in lines)
            {
                sb.Append(line);
            }
            RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;
            if (multiline)
            {
                options |= RegexOptions.Multiline;
            }
            string sbText = sb.ToString();
            string cacheKey = ((uint)options).ToString("X8") + ":" + sbText;

            // allow up to maxCacheSize compiled dynamic regular expression, with minimal config changes/reload, this should last the lifetime of an app
            lock (regexCacheCompiled)
            {
                if (regexCacheCompiled.TryGetValue(cacheKey, out Regex value))
                {
                    return value;
                }
                else if (regexCacheCompiled.Count < maxCacheSize)
                {
                    value = new Regex(sbText, options);
                    regexCacheCompiled.Add(cacheKey, value);
                    return value;
                }
            }

            // have to fall-back to non-compiled regex to avoid run-away memory usage
            try
            {
                lock (regexCacheNotCompiled)
                {
                    if (regexCacheNotCompiled.TryGetValue(cacheKey, out Regex value))
                    {
                        return value;
                    }

                    // strip compiled flag
                    options &= (~RegexOptions.Compiled);
                    value = new Regex(sbText, options);
                    regexCacheNotCompiled.Add(cacheKey, value);
                    return value;
                }
            }
            finally
            {
                // clear non-compield regex cache if it exceeds max size
                lock (regexCacheNotCompiled)
                {
                    if (regexCacheNotCompiled.Count > maxCacheSize)
                    {
                        regexCacheNotCompiled.Clear();
                    }
                }
            }
        }

        /// <summary>
        /// Clean a multi-line string to make it more readable
        /// </summary>
        /// <param name="text">Multi-line string</param>
        /// <returns>Cleaned multi-line string</returns>
        public static string CleanMultilineString(string text)
        {
            text = (text ?? string.Empty).Trim();
            if (text.Length == 0)
            {
                return string.Empty;
            }

            string[] lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            StringBuilder sb = new();
            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();
                if (trimmedLine.Length != 0)
                {
                    sb.Append(trimmedLine);
                    sb.Append('\n');
                }
            }
            return sb.ToString().Trim();
        }

        /// <summary>
        /// Get an ip address and user name out of text using regex. Regex may contain groups named source_[sourcename] to override the source.
        /// </summary>
        /// <param name="regex">Regex</param>
        /// <param name="text">Text</param>
        /// <param name="timestampFormat">Timestamp format</param>
        /// <param name="eventType">Event type</param>
        /// <param name="info">Info</param>
        /// <param name="dns">Dns lookup to resolve ip addresses</param>
        /// <returns>Set of matches from text</returns>
        public static IEnumerable<IPAddressLogEvent> GetIPAddressEventsFromRegex(Regex regex, string text,
            string timestampFormat = null, IPAddressEventType eventType = IPAddressEventType.FailedLogin,
            string info = null, IDnsLookup dns = null)
        {
            const string customSourcePrefix = "source_";

            // if no regex or no text, we are done
            if (regex is null || string.IsNullOrWhiteSpace(text))
            {
                yield break;
            }

            // remove control chars
            text = new string(text.Where(c => c == '\n' || c == '\t' || !char.IsControl(c)).ToArray());

            // go through all the matches and pull out event info
            var matches = regex.Matches(text);
            foreach (var match in matches.Cast<Match>())
            {
                string userName = null;
                string ipAddress = null;
                string foundSource = null;
                string logData = null;
                DateTime timestamp = default;

                // check for a user name
                if (string.IsNullOrWhiteSpace(userName))
                {
                    var userNameGroup = match.Groups["username"];
                    if (userNameGroup != null && userNameGroup.Success)
                    {
                        userName ??= userNameGroup.Value.Trim(regexTrimChars);
                    }
                    else
                    {
                        // sometimes user names are base64, like smtp logs
                        userNameGroup = match.Groups["username_base64"];
                        if (userNameGroup != null && userNameGroup.Success)
                        {
                            // attempt to decode base64 and get the actual user name
                            var base64UserName = userNameGroup.Value;
                            Span<byte> bytes = stackalloc byte[256];
                            if (Convert.TryFromBase64String(base64UserName, bytes, out int bytesWritten))
                            {
                                var base64DecodedUserName = System.Text.Encoding.UTF8.GetString(bytes[..bytesWritten]);
                                userName ??= base64DecodedUserName.Trim(regexTrimChars);
                            }
                        }
                    }
                }

                // check for source
                if (string.IsNullOrWhiteSpace(foundSource))
                {
                    var sourceGroup = match.Groups["source"];
                    if (sourceGroup != null && sourceGroup.Success)
                    {
                        foundSource = sourceGroup.Value.Trim(regexTrimChars);
                    }
                }

                // check for groups with a custom source name
                foreach (var group in match.Groups.Cast<Group>())
                {
                    if (group.Success &&
                        group.Name != null &&
                        string.IsNullOrWhiteSpace(foundSource) &&
                        group.Name.StartsWith(customSourcePrefix))
                    {
                        foundSource = group.Name[customSourcePrefix.Length..];
                    }
                }

                // check for timestamp group
                var timestampGroup = match.Groups["timestamp"];
                if (timestampGroup is not null && timestampGroup.Success)
                {
                    string toParse = timestampGroup.Value.Trim(regexTrimChars);
                    if (string.IsNullOrWhiteSpace(timestampFormat) ||
                        !DateTime.TryParseExact(toParse, timestampFormat.Trim(), CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out timestamp))
                    {
                        DateTime.TryParse(toParse, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out timestamp);
                    }
                }

                // try utc timestamp group, if any
                if (timestamp == default &&
                    (timestampGroup = match.Groups["timestamp_utc"]) is not null &&
                    timestampGroup.Success)
                {
                    string toParse = timestampGroup.Value.Trim(regexTrimChars);
                    if (string.IsNullOrWhiteSpace(timestampFormat) ||
                        !DateTime.TryParseExact(toParse, timestampFormat.Trim(), CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal, out timestamp))
                    {
                        DateTime.TryParse(toParse, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal, out timestamp);
                    }
                }

                // check if the regex had an ipadddress group
                var ipAddressGroup = match.Groups["ipaddress"];
                if (ipAddressGroup is null || !ipAddressGroup.Success)
                {
                    ipAddressGroup = match.Groups["ipaddress_exact"];
                }
                if (ipAddressGroup != null && ipAddressGroup.Success && !string.IsNullOrWhiteSpace(ipAddressGroup.Value))
                {
                    string tempIPAddress = ipAddressGroup.Value.Trim();

                    // in case of IP:PORT format, try a second time, stripping off the :PORT, saves having to do this in all
                    //  the different ip regex.
                    int lastColon = tempIPAddress.LastIndexOf(':');
                    bool isValidIPAddress = IPAddress.TryParse(tempIPAddress, out IPAddress tmp);
                    if (isValidIPAddress || (lastColon >= 0 && IPAddress.TryParse(tempIPAddress[..lastColon], out tmp)))
                    {
                        ipAddress = tmp.ToString();
                    }

                    // if we are parsing anything as ip address (including dns names)
                    if (string.IsNullOrWhiteSpace(ipAddress) &&
                        dns != null &&
                        ipAddressGroup.Name == "ipaddress" &&
                        tempIPAddress != Environment.MachineName &&
                        tempIPAddress != "-")
                    {
                        // Check Host by name
                        Logger.Info("Parsing as IP failed for {0}, info: {1}. Checking dns...", tempIPAddress, info);
                        try
                        {
                            IPAddress[] ipAddresses = dns.GetHostAddressesAsync(tempIPAddress).Sync();
                            if (ipAddresses != null && ipAddresses.Length > 0)
                            {
                                ipAddress = ipAddresses.FirstOrDefault().ToString();
                                Logger.Info("Dns result '{0}' = '{1}'", tempIPAddress, ipAddress);
                            }
                        }
                        catch
                        {
                            Logger.Info("Parsing as dns failed '{0}'", tempIPAddress);
                        }
                    }
                }

                // check for log data
                if (string.IsNullOrWhiteSpace(logData))
                {
                    var logDataGroup = match.Groups["log"];
                    if (logDataGroup is not null && logDataGroup.Success)
                    {
                        logData = logDataGroup.Value;
                    }
                }

                // see if there is a repeat indicator in the message
                int repeatCount = ExtractRepeatCount(match, text);

                // truncate user name if configured
                if (!string.IsNullOrWhiteSpace(userName) && truncateUserNameCharsArray.Length != 0)
                {
                    int truncatePos = userName.IndexOfAny(truncateUserNameCharsArray);
                    if (truncatePos >= 0)
                    {
                        var truncatedUserName = userName[..truncatePos];
                        if (truncatedUserName != userName)
                        {
                            Logger.Info("Truncated user name {0} to {1}", userName, truncatedUserName);
                            userName = truncatedUserName;
                        }
                    }
                }
                else
                {
                    Logger.Debug("Skipping user name truncation since no truncation chars configured");
                }

                // return an event for this match
                yield return new IPAddressLogEvent(ipAddress, userName, foundSource, repeatCount,
                    eventType, timestamp, logData: logData);
            }
        }

        /// <summary>
        /// Validate a regex - returns an error otherwise empty string if success
        /// </summary>
        /// <param name="regex">Regex to validate, can be null or empty</param>
        /// <param name="options">Regex options</param>
        /// <param name="throwException">True to throw the exception instead of returning the string, false otherwise</param>
        /// <returns>Null if success, otherwise an error string indicating the problem</returns>
        public static string ValidateRegex(string regex, RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, bool throwException = false)
        {
            try
            {
                if (regex != null)
                {
                    _ = new Regex(regex, options);
                }
                return null;
            }
            catch (Exception ex)
            {
                if (throwException)
                {
                    throw;
                }
                return ex.Message;
            }
        }

        private static int ExtractRepeatCount(Match match, string text)
        {
            // if the match is optional/empty just return 1
            if (match.Length == 0)
            {
                return 1;
            }

            // look for the first instance of a message repeated text for this match, up to the last newline
            int repeatStart = match.Index;
            int repeatEnd = match.Index + match.Length;
            while (repeatStart > 0)
            {
                if (text[repeatStart] == '\n')
                {
                    repeatStart++;
                    break;
                }
                repeatStart--;
            }
            while (repeatEnd < text.Length)
            {
                if (text[repeatEnd] == '\n')
                {
                    break;
                }
                repeatEnd++;
            }
            Match repeater = Regex.Match(text[repeatStart..repeatEnd],
                "message repeated (?<count>[0-9]+) times", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (repeater.Success)
            {
                return int.Parse(repeater.Groups["count"].Value, CultureInfo.InvariantCulture);
            }
            return 1;
        }
    }
}
