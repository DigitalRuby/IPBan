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
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Parse and create a filter for ips, user names, ip list from urls, regex, etc.
    /// </summary>
    public class IPBanFilter : IIPBanFilter
    {
        private static readonly HashSet<string> ignoreListEntries = new()
        {
            "0.0.0.0",
            "::0",
            "127.0.0.1",
            "::1",
            "localhost"
        };

        private static readonly IEnumerable<KeyValuePair<string, object>> ipListHeaders = new KeyValuePair<string, object>[]
        {
            new KeyValuePair<string, object>("User-Agent", "ipban.com")
        };

        private readonly HashSet<System.Net.IPAddress> set = new();
        private readonly Regex regex;
        private readonly HashSet<IPAddressRange> ranges = new();
        private readonly HashSet<string> others = new(StringComparer.OrdinalIgnoreCase);
        private readonly IDnsServerList dnsList;
        private readonly IIPBanFilter counterFilter;

        private void AddIPAddressRange(IPAddressRange range)
        {
            if (range.Single)
            {
                lock (set)
                {
                    set.Add(range.Begin);
                }
            }
            else
            {
                lock (ranges)
                {
                    ranges.Add(range);
                }
            }
        }

        private bool IsNonIPMatch(string entry)
        {
            if (!string.IsNullOrWhiteSpace(entry))
            {
                entry = entry.Trim().Normalize();

                if (others.Contains(entry))
                {
                    // direct string match in other set
                    return true;
                }

                // fallback to regex match
                if (regex is not null)
                {
                    // try the regex as last resort
                    return regex.IsMatch(entry);
                }
            }

            return false;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">String value to parse</param>
        /// <param name="regexValue">Regex value to parse</param>
        /// <param name="httpRequestMaker">Http request maker in case urls are present in the value</param>
        /// <param name="dns">Dns lookup in case dns entries are present in the value</param>
        /// <param name="dnsList">Dns servers, these are never filtered</param>
        /// <param name="counterFilter">Filter to check first and return false if contains</param>
        public IPBanFilter(string value, string regexValue, IHttpRequestMaker httpRequestMaker, IDnsLookup dns,
            IDnsServerList dnsList, IIPBanFilter counterFilter)
        {
            this.dnsList = dnsList;
            this.counterFilter = counterFilter;

            value = (value ?? string.Empty).Trim();
            regexValue = (regexValue ?? string.Empty).Replace("*", @"[0-9A-Fa-f]+?").Trim();

            if (!string.IsNullOrWhiteSpace(value))
            {
                List<string> entries = new();
                foreach (string entry in value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(e => e.Trim()))
                {
                    string entryWithoutComment = entry;
                    int pos = entryWithoutComment.IndexOf('?');
                    if (pos >= 0)
                    {
                        entryWithoutComment = entryWithoutComment[..pos];
                    }
                    entryWithoutComment = entryWithoutComment.Trim();
                    entries.Add(entryWithoutComment);
                }
                List<Task> entryTasks = new();

                // iterate in parallel for performance
                foreach (string entry in entries)
                {
                    string entryWithoutComment = entry;
                    entryTasks.Add(Task.Run(async () =>
                    {
                        bool isUserName;
                        if (entryWithoutComment.StartsWith("user:", StringComparison.OrdinalIgnoreCase))
                        {
                            isUserName = true;
                            entryWithoutComment = entryWithoutComment["user:".Length..];
                        }
                        else
                        {
                            isUserName = false;
                        }
                        if (!ignoreListEntries.Contains(entryWithoutComment))
                        {
                            if (!isUserName && IPAddressRange.TryParse(entryWithoutComment, out IPAddressRange rangeFromEntry))
                            {
                                AddIPAddressRange(rangeFromEntry);
                            }
                            else if (!isUserName &&
                                (entryWithoutComment.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                                entryWithoutComment.StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
                            {
                                try
                                {
                                    if (httpRequestMaker is not null)
                                    {
                                        // assume url list of ips, newline delimited
                                        byte[] ipListBytes = null;
                                        Uri uri = new(entryWithoutComment);
                                        await ExtensionMethods.RetryAsync(async () => ipListBytes = await httpRequestMaker.MakeRequestAsync(uri, null, ipListHeaders));
                                        string ipList = Encoding.UTF8.GetString(ipListBytes);
                                        if (!string.IsNullOrWhiteSpace(ipList))
                                        {
                                            foreach (string item in ipList.Split('\n'))
                                            {
                                                if (IPAddressRange.TryParse(item.Trim(), out IPAddressRange ipRangeFromUrl))
                                                {
                                                    AddIPAddressRange(ipRangeFromUrl);
                                                }
                                            }
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Logger.Error(ex, "Failed to get ip list from url {0}", entryWithoutComment);
                                }
                            }
                            else if (!isUserName && Uri.CheckHostName(entryWithoutComment) != UriHostNameType.Unknown)
                            {
                                try
                                {
                                    if (dns is not null)
                                    {
                                        // add entries for each ip address that matches the dns entry
                                        IPAddress[] addresses = null;
                                        await ExtensionMethods.RetryAsync(async () => addresses = await dns.GetHostAddressesAsync(entryWithoutComment),
                                            exceptionRetry: _ex =>
                                            {
                                            // ignore host not found errors
                                            return (_ex is not System.Net.Sockets.SocketException socketEx ||
                                                    socketEx.SocketErrorCode != System.Net.Sockets.SocketError.HostNotFound);
                                            });

                                        lock (set)
                                        {
                                            foreach (IPAddress adr in addresses)
                                            {
                                                set.Add(adr);
                                            }
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Logger.Debug("Unable to resolve dns for {0}: {1}", entryWithoutComment, ex.Message);

                                    lock (others)
                                    {
                                        // eat exception, nothing we can do
                                        others.Add(entryWithoutComment);
                                    }
                                }
                            }
                            else
                            {
                                lock (others)
                                {
                                    others.Add(entryWithoutComment);
                                }
                            }
                        }
                    }));
                }

                Task.WhenAll(entryTasks).Sync();
            }

            if (!string.IsNullOrWhiteSpace(regexValue))
            {
                regex = IPBanConfig.ParseRegex(regexValue);
            }
        }

        /// <inheritdoc />
        public bool Equals(IIPBanFilter other)
        {
            if (object.ReferenceEquals(this, other))
            {
                return true;
            }
            else if (other is not IPBanFilter otherFilter)
            {
                return false;
            }
            else if (!set.SetEquals(otherFilter.set))
            {
                return false;
            }
            else if (!ranges.SetEquals(otherFilter.ranges))
            {
                return false;
            }
            else if (regex is not null ^ otherFilter.regex is not null)
            {
                return false;
            }
            else if (regex is not null && otherFilter.regex is not null &&
                !regex.ToString().Equals(otherFilter.Regex.ToString()))
            {
                return false;
            }
            return true;
        }

        /// <inheritdoc />
        public bool IsFiltered(string entry)
        {
            if (IPAddressRange.TryParse(entry, out IPAddressRange ipAddressRange) &&
                IsFiltered(ipAddressRange))
            {
                return true;
            }
            else if (counterFilter is not null && counterFilter.IsFiltered(entry))
            {
                return false;
            }

            // default behavior
            return IsNonIPMatch(entry);
        }

        /// <inheritdoc/>
        public bool IsFiltered(IPAddressRange range)
        {
            // if we have a counter filter or a dns list and one of our dns servers is in the range, the range is not filtered
            if ((counterFilter is not null && counterFilter.IsFiltered(range)) ||
                (dnsList != null && dnsList.ContainsIPAddressRange(range)))
            {
                return false;
            }
            // if the set or ranges contains the range, it is filtered
            else if ((range.Single && set.Contains(range.Begin)) ||
                (set.Any(i => range.Contains(i)) || ranges.Any(r => r.Contains(range))))
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Get all ip address ranges in the filter
        /// </summary>
        public IReadOnlyCollection<IPAddressRange> IPAddressRanges
        {
            get { return set.Select(b => new IPAddressRange(b)).Union(ranges).ToArray(); }
        }

        /// <summary>
        /// Get the regex filter
        /// </summary>
        public Regex Regex => regex;
    }
}
