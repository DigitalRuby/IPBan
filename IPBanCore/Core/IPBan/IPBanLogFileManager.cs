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
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Responsible for managing and parsing log files for failed and successful logins
    /// </summary>
    public class IPBanLogFileManager : IUpdater
    {
        private readonly IIPBanService service;
        private readonly HashSet<IPBanLogFileScanner> logFilesToParse = new();

        /// <summary>
        /// Log files to parse
        /// </summary>
        public IReadOnlyCollection<LogFileScanner> LogFilesToParse { get { return logFilesToParse; } }

        public IPBanLogFileManager(IIPBanService service)
        {
            this.service = service;
            service.ConfigChanged += UpdateLogFiles;
        }

        /// <inheritdoc />
        public Task Update(CancellationToken cancelToken)
        {
            UpdateLogFiles(service.Config);
            if (service.ManualCycle)
            {
                foreach (IPBanLogFileScanner scanner in logFilesToParse)
                {
                    scanner.ProcessFiles();
                }
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            service.ConfigChanged -= UpdateLogFiles;
            foreach (LogFileScanner file in logFilesToParse)
            {
                file.Dispose();
            }
        }

        private void UpdateLogFiles(IPBanConfig newConfig)
        {
            // remove existing log files that are no longer in config
            foreach (IPBanLogFileScanner file in logFilesToParse.ToArray())
            {
                if (newConfig.LogFilesToParse.FirstOrDefault(f => f.PathsAndMasks.Contains(file.PathAndMask)) is null)
                {
                    file.Dispose();
                    logFilesToParse.Remove(file);
                }
            }
            foreach (IPBanLogFileToParse newFile in newConfig.LogFilesToParse)
            {
                string[] pathsAndMasks = newFile.PathsAndMasks;
                for (int i = 0; i < pathsAndMasks.Length; i++)
                {
                    string pathAndMask = pathsAndMasks[i];
                    if (!string.IsNullOrWhiteSpace(pathAndMask))
                    {
                        // if we don't have this log file and the platform matches, add it
                        IPBanLogFileScanner existingScanner = logFilesToParse.FirstOrDefault(f => f.PathAndMask == pathAndMask);

                        IPBanIPAddressLogFileScannerOptions options = new()
                        {
                            Dns = service.DnsLookup,
                            LoginHandler = service,
                            MaxFileSizeBytes = newFile.MaxFileSize,
                            PathAndMask = pathAndMask,
                            PingIntervalMilliseconds = (service.ManualCycle ? 0 : newFile.PingInterval),
                            RegexFailure = IPBanConfig.ParseRegex(newFile.FailedLoginRegex, true),
                            RegexSuccess = IPBanConfig.ParseRegex(newFile.SuccessfulLoginRegex, true),
                            RegexFailureTimestampFormat = newFile.FailedLoginRegexTimestampFormat,
                            RegexSuccessTimestampFormat = newFile.SuccessfulLoginRegexTimestampFormat,
                            Source = newFile.Source,
                            FailedLoginThreshold = newFile.FailedLoginThreshold,
                            FailedLogLevel = newFile.FailedLoginLogLevel,
                            SuccessfulLogLevel = newFile.SuccessfulLoginLogLevel
                        };

                        // if we have an existing log file scanner, but it does not match the new configuration, remove the old log file scanner
                        // and we will add a new one with updated config
                        if (existingScanner is not null && !existingScanner.MatchesOptions(options))
                        {
                            // TODO: Add unit/integration test for this case
                            Logger.Info("Log file options changed for path/mask {0}", pathAndMask);
                            logFilesToParse.RemoveWhere(f => f.PathAndMask == pathAndMask);
                            existingScanner.Dispose();
                            existingScanner = null;
                        }

                        // make sure we match the platform before potentially making a new log file scanner
                        bool platformMatches = !string.IsNullOrWhiteSpace(newFile.PlatformRegex) &&
                            Regex.IsMatch(OSUtility.Description, newFile.PlatformRegex.ToString().Trim(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                        if (existingScanner is null && platformMatches)
                        {
                            // log files use a timer internally and do not need to be updated regularly
                            IPBanLogFileScanner scanner = new(options);
                            logFilesToParse.Add(scanner);
                            Logger.Info("Adding log file to parse: {0}", pathAndMask);
                        }
                        else
                        {
                            Logger.Trace("Ignoring log file path {0}, regex: {1}, no matching file: {2}, platform match: {3}",
                                pathAndMask, newFile.PlatformRegex, existingScanner is null, platformMatches);
                        }
                    }
                }
            }
        }
    }
}
