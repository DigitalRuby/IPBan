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

using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Log file scanner that looks for failed and successful logins
    /// </summary>
    public class IPBanLogFileScanner : LogFileScanner
    {
        private readonly IIPAddressEventHandler eventHandler;
        private readonly IDnsLookup dns;
        private readonly string regexFailureString;
        private readonly Regex regexFailure;
        private readonly string regexSuccessString;
        private readonly Regex regexSuccess;
        private readonly string regexFailureTimestampFormat;
        private readonly string regexSuccessTimestampFormat;

        /// <summary>
        /// The source of the failed login
        /// </summary>
        public string Source { get; }

        /// <summary>
        /// Failed login threshold or 0 for default
        /// </summary>
        public int FailedLoginThreshold { get; }

        /// <summary>
        /// Failed login log level
        /// </summary>
        public LogLevel FailedLogLevel { get; }

        /// <summary>
        /// Successful login log level
        /// </summary>
        public LogLevel SuccessfulLogLevel { get; }

        /// <summary>
        /// Notification flags
        /// </summary>
        public IPAddressNotificationFlags NotificationFlags { get; }

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="options">Options</param>
        public IPBanLogFileScanner(IPBanIPAddressLogFileScannerOptions options) : base(options.PathAndMask, options.MaxFileSizeBytes, options.PingIntervalMilliseconds, options.Encoding, options.MaxLineLength)
        {
            options.ThrowIfNull(nameof(options));
            options.EventHandler.ThrowIfNull(nameof(options.EventHandler));
            options.Dns.ThrowIfNull(nameof(options.Dns));
            Source = options.Source;
            FailedLoginThreshold = options.FailedLoginThreshold;
            FailedLogLevel = options.FailedLogLevel;
            SuccessfulLogLevel = options.SuccessfulLogLevel;
            NotificationFlags = options.NotificationFlags;

            this.eventHandler = options.EventHandler;
            this.dns = options.Dns;

            this.regexFailureString = options.RegexFailure;
            this.regexFailure = IPBanRegexParser.ParseRegex(options.RegexFailure, true);
            this.regexFailureTimestampFormat = options.RegexFailureTimestampFormat;
            this.regexSuccessString = options.RegexSuccess;
            this.regexSuccess = IPBanRegexParser.ParseRegex(options.RegexSuccess, true);
            this.regexSuccessTimestampFormat = options.RegexSuccessTimestampFormat;
        }

        /// <summary>
        /// Check if this log file scanner matches all the provided options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>True if matches options, false otherwise</returns>
        public bool MatchesOptions(IPBanIPAddressLogFileScannerOptions options)
        {
            if (options is null)
            {
                return false;
            }

            return Source == options.Source &&
                FailedLoginThreshold == options.FailedLoginThreshold &&
                FailedLogLevel == options.FailedLogLevel &&
                NotificationFlags == options.NotificationFlags &&
                SuccessfulLogLevel == options.SuccessfulLogLevel &&
                this.eventHandler == options.EventHandler &&
                this.dns == options.Dns &&
                this.regexFailureString == options.RegexFailure &&
                this.regexFailureTimestampFormat == options.RegexFailureTimestampFormat &&
                this.regexSuccessString == options.RegexSuccess &&
                this.regexSuccessTimestampFormat == options.RegexSuccessTimestampFormat;
        }

        /// <inheritdoc />
        protected override void OnProcessText(string text)
        {
            Logger.Debug("Parsing log file text {0}...", text);
            ParseRegex(regexFailure, text, false, regexFailureTimestampFormat);
            ParseRegex(regexSuccess, text, true, regexSuccessTimestampFormat);
        }

        private void ParseRegex(Regex regex, string text, bool successful, string timestampFormat)
        {
            List<IPAddressLogEvent> events = [];
            IPAddressEventType type = (successful ? IPAddressEventType.SuccessfulLogin : IPAddressEventType.FailedLogin);
            foreach (IPAddressLogEvent info in IPBanRegexParser.GetIPAddressEventsFromRegex(regex, text, timestampFormat, type, Source, dns))
            {
                info.Source ??= Source; // apply default source only if we don't already have a source
                if (info.FailedLoginThreshold <= 0)
                {
                    info.FailedLoginThreshold = FailedLoginThreshold;
                }
                if (successful)
                {
                    info.LogLevel = SuccessfulLogLevel;
                }
                else
                {
                    info.LogLevel = FailedLogLevel;
                }
                info.NotificationFlags = NotificationFlags;
                events.Add(info);

                Logger.Debug("Log file found match, ip: {0}, user: {1}, source: {2}, count: {3}, type: {4}",
                    info.IPAddress, info.UserName, info.Source, info.Count, info.Type);
            }
            eventHandler.AddIPAddressLogEvents(events);
        }
    }

    /// <summary>
    /// Options for IPBanIPAddressLogFileScanner
    /// </summary>
    public class IPBanIPAddressLogFileScannerOptions
    {
        /// <summary>
        /// Event handler
        /// </summary>
        public IIPAddressEventHandler EventHandler { get; set; }

        /// <summary>
        /// Dns lookup
        /// </summary>
        public IDnsLookup Dns { get; set; }

        /// <summary>
        /// Default source
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// Folder and file mask to search
        /// </summary>
        public string PathAndMask { get; set; }

        /// <summary>
        /// Regular expression for failed logins, should at minimum have an ipaddress group, but can also have
        /// a timestamp group, source group and username group.
        /// </summary>
        public string RegexFailure { get; set; }

        /// <summary>
        /// Optional date/time format if RegexFailure has a timestamp group
        /// </summary>
        public string RegexFailureTimestampFormat { get; set; }

        /// <summary>
        /// Regular expression for successful logins, see RegexFailure for regex group names.
        /// </summary>
        public string RegexSuccess { get; set; }

        /// <summary>
        /// Optional date/time format if RegexSuccess has a timestamp group
        /// </summary>
        public string RegexSuccessTimestampFormat { get; set; }

        /// <summary>
        /// Max file size for the log file before auto-deleting, default is unlimited
        /// </summary>
        public long MaxFileSizeBytes { get; set; }

        /// <summary>
        /// Interval to ping the log file, default is 0 which means manual ping is required
        /// </summary>
        public int PingIntervalMilliseconds { get; set; }

        /// <summary>
        /// Encoding
        /// </summary>
        public Encoding Encoding { get; set; } = Encoding.UTF8;

        /// <summary>
        /// Max line length or 0 for unlimited - be careful using 0, performance can suffer
        /// </summary>
        public ushort MaxLineLength { get; set; } = 8192;

        /// <summary>
        /// Failed login threshold or 0 for default
        /// </summary>
        public int FailedLoginThreshold { get; set; }

        /// <summary>
        /// Log level for failed logins
        /// </summary>
        public LogLevel FailedLogLevel { get; set; }

        /// <summary>
        /// Log level for successful logins
        /// </summary>
        public LogLevel SuccessfulLogLevel { get; set; }

        /// <summary>
        /// Notification flags
        /// </summary>
        public IPAddressNotificationFlags NotificationFlags { get; set; }
    }
}
