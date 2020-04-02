/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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

using System.Text.RegularExpressions;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Log file scanner that looks for failed logins
    /// </summary>
    public class IPBanIPAddressLogFileScanner : LogFileScanner
    {
        private readonly IIPAddressEventHandler loginHandler;
        private readonly IDnsLookup dns;
        private readonly Regex regexFailure;
        private readonly Regex regexSuccess;
        private readonly string regexFailureTimestampFormat;
        private readonly bool regexFailureMultiline;
        private readonly string regexSuccessTimestampFormat;
        private readonly bool regexSuccessMultiline;

        /// <summary>
        /// The source of the failed login
        /// </summary>
        public string Source { get; }

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="options">Options</param>
        public IPBanIPAddressLogFileScanner(IPBanIPAddressLogFileScannerOptions options) : base(options.PathAndMask, options.Recursive, options.MaxFileSizeBytes, options.PingIntervalMilliseconds)
        {
            options.ThrowIfNull(nameof(options));
            options.LoginHandler.ThrowIfNull(nameof(options.LoginHandler));
            options.Dns.ThrowIfNull(nameof(options.Dns));
            Source = options.Source;

            this.loginHandler = options.LoginHandler;
            this.dns = options.Dns;

            this.regexFailure = IPBanConfig.ParseRegex(options.RegexFailure);
            this.regexFailureTimestampFormat = options.RegexFailureTimestampFormat;
            this.regexFailureMultiline = options.RegexFailure != null && options.RegexFailure.Contains("\\n");

            this.regexSuccess = IPBanConfig.ParseRegex(options.RegexSuccess);
            this.regexSuccessTimestampFormat = options.RegexSuccessTimestampFormat;
            this.regexSuccessMultiline = options.RegexSuccess != null && options.RegexSuccess.Contains("\\n");
        }

        /// <inheritdoc />
        protected override bool OnProcessLine(string[] lines, int index)
        {
            string line = lines[index];
            Logger.Debug("Parsing log file line {0}...", line);
            string failureLine = line;
            if (regexFailureMultiline && index < lines.Length - 1)
            {
                failureLine += "\n" + lines[index + 1];
            }
            bool result = ParseRegex(regexFailure, failureLine, false, regexFailureTimestampFormat);
            if (!result)
            {
                string successLine = line;
                if (regexSuccessMultiline && index < lines.Length - 1)
                {
                    successLine += "\n" + lines[index + 1];
                }
                result = ParseRegex(regexSuccess, successLine, true, regexSuccessTimestampFormat);
                if (!result)
                {
                    Logger.Debug("No match for line {0}", line);
                }
            }
            return true;
        }

        private bool ParseRegex(Regex regex, string line, bool notifyOnly, string timestampFormat)
        {
            if (regex != null)
            {
                IPAddressLogEvent info = IPBanService.GetIPAddressInfoFromRegex(dns, regex, line, timestampFormat);
                if (info.FoundMatch)
                {
                    info.Type = (notifyOnly ? IPAddressEventType.SuccessfulLogin : IPAddressEventType.FailedLogin);
                    info.Source ??= Source; // apply default source only if we don't already have a source
                    Logger.Debug("Log file found match, ip: {0}, user: {1}, source: {2}, count: {3}, type: {4}",
                        info.IPAddress, info.UserName, info.Source, info.Count, info.Type);
                    loginHandler.AddIPAddressLogEvents(new IPAddressLogEvent[] { info });
                    return true;
                }
            }
            return false;
        }
    }

    /// <summary>
    /// Options for IPBanIPAddressLogFileScanner
    /// </summary>
    public class IPBanIPAddressLogFileScannerOptions
    {
        /// <summary>
        /// Login handler
        /// </summary>
        public IIPAddressEventHandler LoginHandler { get; set; }

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
        /// Whether to search PathAndMask recursively further down into the directory structure
        /// </summary>
        public bool Recursive { get; set; }

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
    }
}
