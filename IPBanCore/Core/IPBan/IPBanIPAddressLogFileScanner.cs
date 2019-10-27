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
    public class IPBanIPAddressLogFileScanner : LogFileScanner
    {
        private readonly IIPAddressEventHandler loginHandler;
        private readonly IDnsLookup dns;
        private readonly Regex regexFailure;
        private readonly Regex regexSuccess;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="loginHandler">Interface for handling logins</param>
        /// <param name="dns">Interface for dns lookup</param>
        /// <param name="source">The source, i.e. SSH or SMTP, etc.</param>
        /// <param name="pathAndMask">File path and mask (i.e. /var/log/auth*.log)</param>
        /// <param name="recursive">Whether to parse all sub directories of path and mask recursively</param>
        /// <param name="regexFailure">Regex to parse file lines to pull out failed login ipaddress and username</param>
        /// <param name="regexSuccess">Regex to parse file lines to pull out successful login ipaddress and username</param>
        /// <param name="maxFileSizeBytes">Max size of file (in bytes) before it is deleted or 0 for unlimited</param>
        /// <param name="pingIntervalMilliseconds">Ping interval in milliseconds, less than 1 for manual ping required</param>
        public IPBanIPAddressLogFileScanner
        (
            IIPAddressEventHandler loginHandler,
            IDnsLookup dns,
            string source,
            string pathAndMask,
            bool recursive,
            string regexFailure,
            string regexSuccess,
            long maxFileSizeBytes = 0,
            int pingIntervalMilliseconds = 0
        ) : base(pathAndMask, recursive, maxFileSizeBytes, pingIntervalMilliseconds)
        {
            loginHandler.ThrowIfNull(nameof(loginHandler));
            dns.ThrowIfNull(nameof(dns));
            Source = source;
            this.loginHandler = loginHandler;
            this.dns = dns;
            this.regexFailure = IPBanConfig.ParseRegex(regexFailure);
            this.regexSuccess = IPBanConfig.ParseRegex(regexSuccess);
        }

        /// <summary>
        /// Process a line, checking for ip addresses
        /// </summary>
        /// <param name="line">Line to process</param>
        /// <returns>True</returns>
        protected override bool OnProcessLine(string line)
        {
            Logger.Debug("Parsing log file line {0}...", line);
            bool result = ParseRegex(regexFailure, line, false);
            if (!result)
            {
                result = ParseRegex(regexSuccess, line, true);
                if (!result)
                {
                    Logger.Debug("No match for line {0}", line);
                }
            }
            return true;
        }

        private bool ParseRegex(Regex regex, string line, bool notifyOnly)
        {
            if (regex != null)
            {
                IPAddressLogEvent info = IPBanService.GetIPAddressInfoFromRegex(dns, regex, line);
                if (info.FoundMatch)
                {
                    info.Type = (notifyOnly ? IPAddressEventType.SuccessfulLogin : IPAddressEventType.FailedLogin);
                    info.Source = info.Source ?? Source;
                    Logger.Debug("Log file found match, ip: {0}, user: {1}, source: {2}, count: {3}, type: {4}",
                        info.IPAddress, info.UserName, info.Source, info.Count, info.Type);
                    loginHandler.AddIPAddressLogEvents(new IPAddressLogEvent[] { info });
                    return true;
                }
            }
            return false;
        }
    }
}
