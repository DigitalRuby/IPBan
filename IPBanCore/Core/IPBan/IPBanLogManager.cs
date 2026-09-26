/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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
    /// Responsible for managing and parsing logs for failed and successful logins
    /// </summary>
    public sealed class IPBanLogManager : IUpdater
    {
        private readonly IIPBanService service;
        private readonly HashSet<ILogScanner> logsToParse = [];

        /// <summary>
        /// Log files to parse
        /// </summary>
        public IReadOnlyCollection<ILogScanner> LogFilesToParse { get { return logsToParse; } }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="service">Service</param>
        public IPBanLogManager(IIPBanService service)
        {
            this.service = service;
            service.ConfigChanged += UpdateLogFiles;
        }

        /// <inheritdoc />
        public Task Update(CancellationToken cancelToken)
        {
            if (service.ManualCycle)
            {
                foreach (var scanner in logsToParse)
                {
                    scanner.Update();
                }
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            GC.SuppressFinalize(this);

            service.ConfigChanged -= UpdateLogFiles;
            foreach (var file in logsToParse)
            {
                file.Dispose();
            }
        }

        private void UpdateLogFiles(IPBanConfig newConfig)
        {
            // remove existing scanners that are no longer represented in config (by id+path when id is set, otherwise by path)
            foreach (var file in logsToParse.ToArray())
            {
                bool stillConfigured;
                if (!string.IsNullOrWhiteSpace(file.Id))
                {
                    stillConfigured = newConfig.LogFilesToParse.Any(f =>
                        !string.IsNullOrWhiteSpace(f.Id) &&
                        f.Id.Equals(file.Id, StringComparison.OrdinalIgnoreCase) &&
                        f.PathsAndMasks.Contains(file.PathAndMask));
                }
                else
                {
                    stillConfigured = newConfig.LogFilesToParse.Any(f =>
                        string.IsNullOrWhiteSpace(f.Id) &&
                        f.PathsAndMasks.Contains(file.PathAndMask));
                }

                if (!stillConfigured)
                {
                    file.Dispose();
                    logsToParse.Remove(file);
                }
            }
            foreach (var newFile in newConfig.LogFilesToParse)
            {
                string[] pathsAndMasks = newFile.PathsAndMasks;
                for (int i = 0; i < pathsAndMasks.Length; i++)
                {
                    string pathAndMask = pathsAndMasks[i];
                    if (!string.IsNullOrWhiteSpace(pathAndMask))
                    {
                        // When an id is present, match on id + path so multiple entries (and multi-path
                        // entries) can share a directory. Without an id, match only other no-id scanners
                        // on the same path so id'd scanners are not overwritten.
                        var existingScanner = !string.IsNullOrWhiteSpace(newFile.Id)
                            ? logsToParse.FirstOrDefault(f =>
                                f.PathAndMask == pathAndMask &&
                                !string.IsNullOrWhiteSpace(f.Id) &&
                                f.Id.Equals(newFile.Id, StringComparison.OrdinalIgnoreCase))
                            : logsToParse.FirstOrDefault(f =>
                                f.PathAndMask == pathAndMask &&
                                string.IsNullOrWhiteSpace(f.Id));

                        LogScannerOptions options = new()
                        {
                            Dns = service.DnsLookup,
                            EventHandler = service,
                            Id = newFile.Id?.Trim(),
                            MaxFileSizeBytes = newFile.MaxFileSize,
                            PathAndMask = pathAndMask,
                            PingIntervalMilliseconds = (service.ManualCycle ? 0 : newFile.PingInterval),
                            RegexFailure = newFile.FailedLoginRegex,
                            RegexSuccess = newFile.SuccessfulLoginRegex,
                            RegexFailureTimestampFormat = newFile.FailedLoginRegexTimestampFormat,
                            RegexSuccessTimestampFormat = newFile.SuccessfulLoginRegexTimestampFormat,
                            MinimumTimeBetweenFailedLoginAttempts = newFile.MinimumTimeBetweenFailedLoginAttempts.ParseTimeSpan(),
                            Source = newFile.Source,
                            FailedLoginThreshold = newFile.FailedLoginThreshold,
                            FailedLogLevel = newFile.FailedLoginLogLevel,
                            SuccessfulLogLevel = newFile.SuccessfulLoginLogLevel,
                            NotificationFlags = newFile.NotificationFlags,
                            Description = newFile.Description
                        };

                        // if we have an existing log file scanner, but it does not match the new configuration, remove the old log file scanner
                        // and we will add a new one with updated config
                        if (existingScanner is not null &&
                            !existingScanner.MatchesOptions(options))
                        {
                            if (string.IsNullOrWhiteSpace(existingScanner.Id) ||
                                string.IsNullOrWhiteSpace(options.Id))
                            {
                                // without ids, path collision replaces the existing no-id scanner — notify so the user can add ids or use junctions
                                Logger.Info("Multiple log file scanners detected with identical path and mask {0}. Either add ids or use junctions if you need multiple log file scanners on the same directory.", existingScanner.PathAndMask);
                                logsToParse.RemoveWhere(f => f.PathAndMask == pathAndMask && string.IsNullOrWhiteSpace(f.Id));
                            }
                            else
                            {
                                // same id + path, options changed — replace only this scanner
                                logsToParse.Remove(existingScanner);
                            }

                            Logger.Info("Log file options changed for path/mask {0}", pathAndMask);
                            existingScanner.Dispose();
                            existingScanner = null;
                        }

                        // make sure we match the platform before potentially making a new log file scanner
                        var regexToMatch = newFile.PlatformRegex?.ToString()?.Trim();
                        var regexOptions = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
                        bool platformMatches = !string.IsNullOrWhiteSpace(regexToMatch) &&
                            (Regex.IsMatch(OSUtility.Description, regexToMatch, regexOptions, RegexUtility.MatchTimeout) ||
                            Regex.IsMatch(OSUtility.Name, regexToMatch, regexOptions, RegexUtility.MatchTimeout));

                        if (existingScanner is null && platformMatches)
                        {
                            service.AddLogScanner(options, logsToParse);
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
