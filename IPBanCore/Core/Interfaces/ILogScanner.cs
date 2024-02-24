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

using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Scan logs for failed or success attempts
    /// </summary>
    public interface ILogScanner : IDisposable
    {
        /// <summary>
        /// Path and mask (can be files, db connection string, etc.)
        /// </summary>
        string PathAndMask { get; }

        /// <summary>
        /// Check if this scanner matches existing options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>True if match, false otherwise</returns>
        bool MatchesOptions(LogScannerOptions options);

        /// <summary>
        /// Perform processing
        /// </summary>
        void Update();
    }

    /// <summary>
    /// Options for log scanning
    /// </summary>
    public sealed class LogScannerOptions
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

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (obj is LogScannerOptions other)
            {
                return
                    (EventHandler == other.EventHandler) &&
                    (Dns == other.Dns) &&
                    (Source == other.Source) &&
                    (PathAndMask == other.PathAndMask) &&
                    (RegexFailure == other.RegexFailure) &&
                    (RegexFailureTimestampFormat == other.RegexFailureTimestampFormat) &&
                    (RegexSuccess == other.RegexSuccess) &&
                    (RegexSuccessTimestampFormat == other.RegexSuccessTimestampFormat) &&
                    (MaxFileSizeBytes == other.MaxFileSizeBytes) &&
                    (PingIntervalMilliseconds == other.PingIntervalMilliseconds) &&
                    (Encoding == other.Encoding) &&
                    (MaxLineLength == other.MaxLineLength) &&
                    (FailedLoginThreshold == other.FailedLoginThreshold) &&
                    (FailedLogLevel == other.FailedLogLevel) &&
                    (SuccessfulLogLevel == other.SuccessfulLogLevel) &&
                    (NotificationFlags == other.NotificationFlags);
            }
            return false;
        }
    }
}
