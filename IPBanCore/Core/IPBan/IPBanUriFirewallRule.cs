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
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Create a block firewall rule from ip addresses from a uri
    /// </summary>
    public class IPBanUriFirewallRule : IUpdater
    {
        private static readonly string[] commentDelimiters =
        [
            "#",
            "'",
            "REM",
            ";",
            "//"
        ];

        private static readonly TimeSpan fiveSeconds = TimeSpan.FromSeconds(5.0);
        private static readonly TimeSpan thirtySeconds = TimeSpan.FromSeconds(30.0);

        private readonly IIPBanFirewall firewall;
        private readonly IFirewallTaskRunner firewallTaskRunner;
        private readonly IIsWhitelisted whitelistChecker;
        private readonly IHttpRequestMaker httpRequestMaker;
        private readonly HttpClient httpClient;

        private DateTime lastRun;

        /// <summary>
        /// Rule prefix
        /// </summary>
        public string RulePrefix { get; }

        /// <summary>
        /// Interval
        /// </summary>
        public TimeSpan Interval { get; }

        /// <summary>
        /// Uri
        /// </summary>
        public Uri Uri { get; }

        /// <summary>
        /// Max count of ips that can be returned
        /// </summary>
        public int MaxCount { get; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="firewall">Firewall</param>
        /// <param name="firewallTaskRunner">The firewall task runner (must not be null)</param>
        /// <param name="whitelistChecker">Whitelist checker (can be null)</param>
        /// <param name="httpRequestMaker">Http request maker for http uris (must not be null)</param>
        /// <param name="rulePrefix">Firewall rule prefix</param>
        /// <param name="interval">Interval to check uri for changes</param>
        /// <param name="uri">Uri, can be either file or http(s).</param>
        /// <param name="maxCount">Max count of ips that can come from the rule or less than or equal to 0 for infinite.</param>
        public IPBanUriFirewallRule(IIPBanFirewall firewall,
            IFirewallTaskRunner firewallTaskRunner,
            IIsWhitelisted whitelistChecker,
            IHttpRequestMaker httpRequestMaker,
            string rulePrefix,
            TimeSpan interval, Uri uri, int maxCount = 10000)
        {
            this.firewall = firewall.ThrowIfNull();
            this.firewallTaskRunner = firewallTaskRunner.ThrowIfNull();
            this.whitelistChecker = whitelistChecker;
            this.httpRequestMaker = httpRequestMaker.ThrowIfNull();
            RulePrefix = rulePrefix.ThrowIfNull();
            Uri = uri.ThrowIfNull();
            Interval = (interval.TotalSeconds < 5.0 ? fiveSeconds : interval);
            MaxCount = maxCount;

            if (!uri.IsFile)
            {
                httpClient = new HttpClient { Timeout = thirtySeconds };
            }
        }

        /// <summary>
        /// Cleanup all resources
        /// </summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            httpClient?.Dispose();
        }

        /// <summary>
        /// Convert to a string
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return $"Prefix: {RulePrefix}, Interval: {Interval}, Uri: {Uri}";
        }

        /// <summary>
        /// Get hash code for this uri firewall rule
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return Uri.GetHashCode();
        }

        /// <summary>
        /// Check if equal to another object
        /// </summary>
        /// <param name="obj">Other object</param>
        /// <returns>True if equal, false otherwise</returns>
        public override bool Equals(object obj)
        {
            if (obj is not IPBanUriFirewallRule rule)
            {
                return false;
            }
            return (RulePrefix.Equals(rule.RulePrefix) && Uri.Equals(rule.Uri) && Interval.Equals(rule.Interval));
        }

        /// <summary>
        /// Update the updater
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task</returns>
        public async Task Update(CancellationToken cancelToken = default)
        {
            DateTime now = IPBanService.UtcNow;
            if ((now - lastRun) >= Interval)
            {
                lastRun = now;
                if (Uri.IsFile)
                {
                    string filePath = Uri.LocalPath;
                    if (File.Exists(filePath))
                    {
                        string text;
                        if (filePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                        {
                            using var fs = File.OpenRead(filePath);
                            var bytes = DecompressBytes(fs);
                            text = Encoding.UTF8.GetString(bytes);
                        }
                        else
                        {
                            text = await File.ReadAllTextAsync(filePath, cancelToken);
                        }
                        ProcessResult(text, cancelToken);
                    }
                }
                else
                {
                    string newUri = Uri.ToString().Replace("$ts$", IPBanService.UtcNow.Ticks.ToStringInvariant());
                    byte[] bytes = await httpRequestMaker.MakeRequestAsync(new Uri(newUri), cancelToken: cancelToken);
                    string text = Encoding.UTF8.GetString(bytes);
                    ProcessResult(text, cancelToken);
                }
            }
        }

        /// <summary>
        /// Delete firewall rules that may have been created by this rule
        /// </summary>
        public void DeleteRule()
        {
            firewallTaskRunner.RunFirewallTask((state, cancelToken) =>
            {
                foreach (string ruleName in firewall.GetRuleNames(RulePrefix).ToArray())
                {
                    firewall.DeleteRule(ruleName);
                }
                return Task.CompletedTask;
            }, string.Empty, nameof(IPBanFirewallRule) + "." + nameof(DeleteRule));
        }

        private void ProcessResult(string text, CancellationToken cancelToken)
        {
            using StringReader reader = new(text);
            string line;
            List<IPAddressRange> ranges = [];
            int lines = 0;

            while ((line = reader.ReadLine()) != null)
            {
                if (lines++ > MaxCount)
                {
                    // prevent too many lines from crashing us
                    break;
                }

                foreach (string commentDelimiter in commentDelimiters)
                {
                    int pos = line.IndexOf(commentDelimiter);
                    if (pos >= 0)
                    {
                        line = line[..pos];
                    }
                }
                line = line.Trim();

                if (line.Length == 0 || !IPAddressRange.TryParse(line, out IPAddressRange range))
                {
                    continue;
                }
                else if (whitelistChecker is null || !whitelistChecker.IsWhitelisted(range))
                {
                    // make sure to add only ranges that are not whitelisted
                    ranges.Add(range);
                }
            }

            var sortedDistinct = ranges.OrderBy(r => r).Combine().ToArray();

            Logger.Warn("Updating firewall uri rule {0} with {1} ips", RulePrefix, sortedDistinct.Length);

            firewallTaskRunner.RunFirewallTask((state, cancelToken) =>
            {
                return firewall.BlockIPAddresses(RulePrefix, sortedDistinct, null, cancelToken);
            }, string.Empty, nameof(IPBanUriFirewallRule) + "." + nameof(ProcessResult));
        }

        private static byte[] DecompressBytes(Stream input)
        {
            MemoryStream decompressdStream = new();
            {
                using GZipStream gz = new(input, CompressionMode.Decompress, true);
                gz.CopyTo(decompressdStream);
            }
            return decompressdStream.ToArray();
        }
    }
}
