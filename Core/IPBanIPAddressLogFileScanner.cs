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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace IPBan
{
    public class IPBanIPAddressLogFileScanner : IPBanLogFileScanner
    {
        private readonly IFailedLogin failedLogin;
        private readonly IDnsLookup dns;
        private readonly Regex regex;

        /// <summary>
        /// Create a log file scanner
        /// </summary>
        /// <param name="failedLogin">Interface for handling failed logins</param>
        /// <param name="dns">Interface for dns lookup</param>
        /// <param name="source">The source, i.e. SSH or SMTP, etc.</param>
        /// <param name="pathAndMask">File path and mask (i.e. /var/log/auth*.log)</param>
        /// <param name="recursive">Whether to parse all sub directories of path and mask recursively</param>
        /// <param name="regex">Regex to parse file lines to pull out ipaddress and username</param>
        /// <param name="maxFileSize">Max size of file before it is deleted or 0 for unlimited</param>
        /// <param name="pingIntervalMilliseconds">Ping interval in milliseconds, less than 1 for manual ping required</param>
        public IPBanIPAddressLogFileScanner(IFailedLogin failedLogin, IDnsLookup dns,
            string source, string pathAndMask, bool recursive, string regex, long maxFileSize = 0, int pingIntervalMilliseconds = 0) :
            base(pathAndMask, recursive, maxFileSize, pingIntervalMilliseconds)
        {
            failedLogin.ThrowIfNull(nameof(failedLogin));
            dns.ThrowIfNull(nameof(dns));
            Source = source;
            this.failedLogin = failedLogin;
            this.dns = dns;
            this.regex = IPBanConfig.ParseRegex(regex);
        }

        /// <summary>
        /// Process a line, checking for ip addresses
        /// </summary>
        /// <param name="line">Line to process</param>
        /// <returns>True</returns>
        protected override bool OnProcessLine(string line)
        {
            IPBanLog.Debug("Parsing log file line {0}...", line);
            IPAddressLogInfo info = IPBanService.GetIPAddressInfoFromRegex(dns, regex, line);
            if (info.FoundMatch)
            {
                info.Source = info.Source ?? Source;
                IPBanLog.Debug("Log file found match, ip: {0}, user: {1}, source: {2}, count: {3}", info.IPAddress, info.UserName, info.Source, info.Count);
                failedLogin.AddFailedLogin(info);
            }
            else
            {
                IPBanLog.Debug("No match for line {0}", line);
            }

            return true;
        }
    }
}
