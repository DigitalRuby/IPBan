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
    /// Configuration for ip ban app
    /// </summary>
    public sealed class IPBanConfig : IIsWhitelisted
    {
        /// <summary>
        /// Allow temporary change of config
        /// </summary>
        public class TempConfigChanger : IDisposable
        {
            private readonly IConfigReaderWriter config;
            private readonly string origConfig;
            private readonly string modifiedConfig;

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="config">Config</param>
            /// <param name="modifier">Config modifier</param>
            public TempConfigChanger(IConfigReaderWriter config, Func<string, string> modifier) :
                this(config, modifier, out _)
            {
            }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="config">Config</param>
            /// <param name="modifier">Config modifier</param>
            /// <param name="modifiedConfig">Receives modified config</param>
            public TempConfigChanger(IConfigReaderWriter config, Func<string, string> modifier, out string modifiedConfig)
            {
                this.config = config;
                origConfig = config.ReadConfigAsync().Sync();
                this.modifiedConfig = modifiedConfig = modifier(origConfig);
                config.WriteConfigAsync(this.modifiedConfig).Sync();
                if (config is IIPBanService service)
                {
                    service.RunCycleAsync().Sync();
                }
            }

            /// <summary>
            /// Revert config back to original value
            /// </summary>
            public void Dispose()
            {
                GC.SuppressFinalize(this);
                config.WriteConfigAsync(origConfig).Sync();
            }

            /// <summary>
            /// Get the modified config
            /// </summary>
            public string ModifiedConfig => modifiedConfig;
        }

        /// <summary>
        /// Default config file name
        /// </summary>
        public const string DefaultFileName = "ipban.config";

        private static readonly TimeSpan[] emptyTimeSpanArray = new TimeSpan[] { TimeSpan.Zero };
        private static readonly IPBanLogFileToParse[] emptyLogFilesToParseArray = Array.Empty<IPBanLogFileToParse>();
        private static readonly TimeSpan maxBanTimeSpan = TimeSpan.FromDays(90.0);

        private readonly Dictionary<string, string> appSettings = new(StringComparer.OrdinalIgnoreCase);
        private readonly IPBanLogFileToParse[] logFiles;
        private readonly TimeSpan[] banTimes = new TimeSpan[] { TimeSpan.FromDays(1.0d) };
        private readonly TimeSpan expireTime = TimeSpan.FromDays(1.0d);
        private readonly TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private readonly TimeSpan minimumTimeBetweenFailedLoginAttempts = TimeSpan.FromSeconds(5.0);
        private readonly TimeSpan minimumTimeBetweenSuccessfulLoginAttempts = TimeSpan.FromSeconds(5.0);

        private readonly string ipThreatApiKey = string.Empty;
        private readonly int failedLoginAttemptsBeforeBan = 5;
        private readonly bool resetFailedLoginCountForUnbannedIPAddresses;
        private readonly string firewallRulePrefix = "IPBan_";
        private readonly IPBanFilter whitelistFilter;
        private readonly IPBanFilter blacklistFilter;

        private readonly bool clearBannedIPAddressesOnRestart;
        private readonly bool clearFailedLoginsOnSuccessfulLogin;
        private readonly bool processInternalIPAddresses;
        private readonly string truncateUserNameChars = string.Empty;
        private readonly HashSet<string> userNameWhitelist = new(StringComparer.Ordinal);
        private readonly int userNameWhitelistMaximumEditDistance = 2;
        private readonly Regex userNameWhitelistRegex;
        private readonly int failedLoginAttemptsBeforeBanUserNameWhitelist = 20;
        private readonly string processToRunOnBan = string.Empty;
        private readonly string processToRunOnUnban = string.Empty;
        private readonly bool useDefaultBannedIPAddressHandler;
        private readonly string getUrlUpdate = string.Empty;
        private readonly string getUrlStart = string.Empty;
        private readonly string getUrlStop = string.Empty;
        private readonly string getUrlConfig = string.Empty;
        private readonly string firewallUriRules = string.Empty;
        private readonly List<IPBanFirewallRule> extraRules = new();
        private readonly EventViewerExpressionsToBlock expressionsFailure;
        private readonly EventViewerExpressionsToNotify expressionsSuccess;

        /// <summary>
        /// Static constructor - migrate config file from DigitalRuby.IPBan.dll.config to ipban.config
        /// </summary>
        static IPBanConfig()
        {
            string oldConfigPath = null;
            string newConfigPath = null;

            try
            {
                // move DigitalRuby.IPBan.dll.config to ipban.config
                oldConfigPath = Path.Combine(AppContext.BaseDirectory, "DigitalRuby.IPBan.dll.config");
                newConfigPath = Path.Combine(AppContext.BaseDirectory, "ipban.config");
                if (File.Exists(oldConfigPath))
                {
                    ExtensionMethods.Retry(() =>
                    {
                        File.Copy(oldConfigPath, newConfigPath, true);
                        File.Delete(oldConfigPath);
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to copy old config file at {0} to new config file at {1}",
                    oldConfigPath, newConfigPath);
            }
        }

        private IPBanConfig(XmlDocument doc, IDnsLookup dns = null, IDnsServerList dnsList = null, IHttpRequestMaker httpRequestMaker = null)
        {
            // deserialize with XmlDocument for fine grained control
            var appSettingsNodes = doc.SelectNodes("/configuration/appSettings/add");
            if (appSettingsNodes is null || appSettingsNodes.Count == 0)
            {
                throw new InvalidDataException("Configuration is missing or has empty /configuration/appSettings element. This element name is case sensitive. Please check your config.");
            }
            foreach (XmlNode node in appSettingsNodes)
            {
                appSettings[node.Attributes["key"].Value] = node.Attributes["value"].Value;
            }

            TryGetConfig<string>("IPThreatApiKey", ref ipThreatApiKey, false);
            GetConfig<int>("FailedLoginAttemptsBeforeBan", ref failedLoginAttemptsBeforeBan, 1, 50);
            TryGetConfig<bool>("ResetFailedLoginCountForUnbannedIPAddresses", ref resetFailedLoginCountForUnbannedIPAddresses);
            GetConfigArray<TimeSpan>("BanTime", ref banTimes, emptyTimeSpanArray);
            MakeBanTimesValid(ref banTimes);
            TryGetConfig<bool>("ClearBannedIPAddressesOnRestart", ref clearBannedIPAddressesOnRestart);
            TryGetConfig<bool>("ClearFailedLoginsOnSuccessfulLogin", ref clearFailedLoginsOnSuccessfulLogin);
            TryGetConfig<bool>("ProcessInternalIPAddresses", ref processInternalIPAddresses);
            TryGetConfig<string>("TruncateUserNameChars", ref truncateUserNameChars);
            IPBanRegexParser.TruncateUserNameChars = truncateUserNameChars;
            GetConfig<TimeSpan>("ExpireTime", ref expireTime, TimeSpan.Zero, maxBanTimeSpan);
            if (expireTime.TotalMinutes < 1.0)
            {
                expireTime = maxBanTimeSpan;
            }
            GetConfig<TimeSpan>("CycleTime", ref cycleTime, TimeSpan.FromSeconds(5.0), TimeSpan.FromMinutes(1.0), false);
            GetConfig<TimeSpan>("MinimumTimeBetweenFailedLoginAttempts", ref minimumTimeBetweenFailedLoginAttempts, TimeSpan.Zero, TimeSpan.FromSeconds(15.0), false);
            TryGetConfig<string>("FirewallRulePrefix", ref firewallRulePrefix);

            string whitelistString = GetConfig<string>("Whitelist", string.Empty);
            string whitelistRegexString = GetConfig<string>("WhitelistRegex", string.Empty);
            string blacklistString = GetConfig<string>("Blacklist", string.Empty);
            string blacklistRegexString = GetConfig<string>("BlacklistRegex", string.Empty);
            whitelistFilter = new IPBanFilter(whitelistString, whitelistRegexString, httpRequestMaker, dns, dnsList, null);
            blacklistFilter = new IPBanFilter(blacklistString, blacklistRegexString, httpRequestMaker, dns, dnsList, whitelistFilter);
            expressionsFailure = ParseEventViewer<EventViewerExpressionsToBlock>(doc, "/configuration/ExpressionsToBlock", false);
            expressionsSuccess = ParseEventViewer<EventViewerExpressionsToNotify>(doc, "/configuration/ExpressionsToNotify", true);
            logFiles = ParseLogFiles(doc, "/configuration/LogFilesToParse");

            TryGetConfig<string>("ProcessToRunOnBan", ref processToRunOnBan);
            processToRunOnBan = processToRunOnBan?.Trim();
            TryGetConfig<string>("ProcessToRunOnUnban", ref processToRunOnUnban);
            processToRunOnUnban = processToRunOnUnban?.Trim();
            TryGetConfig<bool>("UseDefaultBannedIPAddressHandler", ref useDefaultBannedIPAddressHandler);

            string userNameWhitelistString = GetConfig<string>("UserNameWhitelist", string.Empty);
            if (!string.IsNullOrEmpty(userNameWhitelistString))
            {
                foreach (string userName in userNameWhitelistString.Split(','))
                {
                    string userNameTrimmed = userName.Normalize().ToUpperInvariant().Trim();
                    userNameWhitelist.Add(userNameTrimmed);
                }
            }
            string userNameWhitelistRegexString = GetConfig<string>("UserNameWhitelistRegex", string.Empty);
            if (!string.IsNullOrWhiteSpace(userNameWhitelistRegexString))
            {
                userNameWhitelistRegex = new Regex(userNameWhitelistRegexString, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline);
            }
            TryGetConfig<int>("UserNameWhitelistMinimumEditDistance", ref userNameWhitelistMaximumEditDistance);
            TryGetConfig<int>("FailedLoginAttemptsBeforeBanUserNameWhitelist", ref failedLoginAttemptsBeforeBanUserNameWhitelist);
            TryGetConfig<string>("GetUrlUpdate", ref getUrlUpdate);
            TryGetConfig<string>("GetUrlStart", ref getUrlStart);
            TryGetConfig<string>("GetUrlStop", ref getUrlStop);
            TryGetConfig<string>("GetUrlConfig", ref getUrlConfig);
            TryGetConfig<string>("FirewallUriRules", ref firewallUriRules);
            if (string.IsNullOrWhiteSpace(firewallUriRules))
            {
                // legacy
                TryGetConfig<string>("FirewallUriSources", ref firewallUriRules, false);
            }
            firewallUriRules = (firewallUriRules ?? string.Empty).Trim();

            // parse firewall block rules, one per line
            ParseFirewallBlockRules();

            // set the xml
            Xml = doc.OuterXml;
        }

        private string GetAppSettingsValue(string key, bool logMissing = true)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                // bad key
                Logger.Warn("Ignoring null/empty key");
                return null;
            }
            else if (!appSettings.ContainsKey(key))
            {
                if (logMissing)
                {
                    Logger.Warn("Ignoring key {0}, not found in appSettings", key);
                }
                return null; // skip trying to convert
            }

            // read value from appSettings
            var stringValue = appSettings[key];

            // config value can be read from env var if value starts and ends with %
            if (stringValue.StartsWith("%") && stringValue.EndsWith("%"))
            {
                // read value from environment variable
                stringValue = Environment.GetEnvironmentVariable(stringValue.Trim('%'))?.Trim() ?? string.Empty;
            }

            return stringValue;
        }

        private static void MakeBanTimesValid(ref TimeSpan[] banTimes)
        {
            var newBanTimes = new List<TimeSpan>();
            TimeSpan max = TimeSpan.MinValue;
            for (int i = 0; i < banTimes.Length; i++)
            {
                // according to documentation, a ban time of 0 should become max ban time
                if (banTimes[i].Ticks <= 0)
                {
                    banTimes[i] = maxBanTimeSpan;
                }
                else
                {
                    banTimes[i] = banTimes[i].Clamp(TimeSpan.FromMinutes(1.0), maxBanTimeSpan);
                }
                // Ensure all times are in strictly ascending order. We remember the up to i largest span in max. If a new span is smaller we have an issue.
                // It is not enough to check banTimes[i-1] >= banTimes[i]. Example: 5,2,3 -> 2 would be skipped but not 3 which is also violating the order.
                if (i > 0 && max >= banTimes[i])
                {
                    Logger.Error($"BanTime: Multiple time spans must be in strictly ascending order. This is not the case for {banTimes[i]}. Ignoring this entry.");
                }
                else
                {
                    max = banTimes[i];
                    newBanTimes.Add(max);
                }
            }
            banTimes = newBanTimes.ToArray();
        }

        private static readonly ConcurrentDictionary<Type, XmlSerializer> eventViewerSerializers = new();

        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        private static T ParseEventViewer<T>(XmlDocument doc, string path, bool notifyOnly) where T : EventViewerExpressions, new()
        {
            XmlNode node = doc.SelectSingleNode(path);
            T eventViewerExpressions = null;
            if (node != null)
            {
                try
                {
                    XmlSerializer configDeserializer = eventViewerSerializers.GetOrAdd(typeof(T), new XmlSerializer(typeof(T)));
                    eventViewerExpressions = configDeserializer.Deserialize(new XmlNodeReader(node)) as T;
                }
                catch (Exception ex)
                {
                    Logger.Error("Failed to load event viewer expressions of type " + typeof(T).FullName, ex);
                    eventViewerExpressions = new T { Groups = new List<EventViewerExpressionGroup>() };
                }
                foreach (EventViewerExpressionGroup group in eventViewerExpressions.Groups)
                {
                    group.NotifyOnly = notifyOnly;
                    foreach (EventViewerExpression expression in group.Expressions)
                    {
                        expression.Regex = (expression.Regex?.ToString() ?? string.Empty).Trim();
                    }
                }
            }
            return eventViewerExpressions;
        }

        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        private static readonly XmlSerializer logFileDeserializer = new(typeof(IPBanLogFilesToParse));

        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        private static IPBanLogFileToParse[] ParseLogFiles(XmlDocument doc, string path)
        {
            IPBanLogFileToParse[] logFiles;
            try
            {
                XmlNode logFilesToParseNode = doc.SelectSingleNode(path);
                if (logFilesToParseNode != null && logFileDeserializer.Deserialize(new XmlNodeReader(logFilesToParseNode)) is IPBanLogFilesToParse logFilesToParse)
                {
                    logFiles = logFilesToParse.LogFiles;
                }
                else
                {
                    logFiles = emptyLogFilesToParseArray;
                }
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to load log files from xml", ex);
                logFiles = emptyLogFilesToParseArray;
            }
            return logFiles;
        }

        private void ParseFirewallBlockRules()
        {
            string firewallRulesString = null;
            TryGetConfig<string>("FirewallRules", ref firewallRulesString);
            firewallRulesString = (firewallRulesString ?? string.Empty).Trim();
            if (firewallRulesString.Length == 0)
            {
                return;
            }
            IEnumerable<string> firewallRuleStrings = firewallRulesString.Trim().Split('\n').Select(s => s.Trim()).Where(s => s.Length != 0);
            foreach (string firewallRuleString in firewallRuleStrings)
            {
                string[] pieces = firewallRuleString.Split(';');
                if (pieces.Length == 5)
                {
                    IPBanFirewallRule firewallRuleObj = new()
                    {
                        Block = (pieces[1].Equals("block", StringComparison.OrdinalIgnoreCase)),
                        IPAddressRanges = pieces[2].Split(',').Select(p => IPAddressRange.Parse(p)).ToList(),
                        Name = "EXTRA_" + pieces[0].Trim(),
                        AllowPortRanges = pieces[3].Split(',').Select(p => PortRange.Parse(p)).Where(p => p.MinPort >= 0).ToList(),
                        PlatformRegex = new Regex(pieces[4].Replace('*', '.'), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
                    };
                    if (firewallRuleObj.PlatformRegex.IsMatch(OSUtility.Name))
                    {
                        extraRules.Add(firewallRuleObj);
                    }
                }
                else
                {
                    Logger.Warn("Firewall block rule entry should have 5 comma separated pieces: name;block/allow;ips;ports;platform_regex. Invalid entry: {0}", firewallRuleString);
                }
            }
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return Xml;
        }

        /// <summary>
        /// Get a value from configuration manager app settings
        /// </summary>
        /// <typeparam name="T">Type of value to get</typeparam>
        /// <param name="key">Key</param>
        /// <param name="defaultValue">Default value if null or not found</param>
        /// <returns>Value or defaultValue if not found</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public T GetConfig<T>(string key, T defaultValue = default)
        {
            T value = defaultValue;
            TryGetConfig(key, ref value);
            return value;
        }

        /// <summary>
        /// Set a field / variable from configuration manager app settings. If null or not found, nothing is changed.
        /// </summary>
        /// <typeparam name="T">Type of value to set</typeparam>
        /// <param name="key">Key</param>
        /// <param name="value">Value. Can start and end with % to read from env var</param>
        /// <param name="logMissing">Whether to log missing keys</param>
        /// <returns>True if config found, false if not</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public bool TryGetConfig<T>(string key, ref T value, bool logMissing = true)
        {
            try
            {
                var stringValue = GetAppSettingsValue(key, logMissing);

                if (!string.IsNullOrWhiteSpace(stringValue))
                {
                    // deserialize string value
                    value = (T)TypeDescriptor.GetConverter(typeof(T)).ConvertFromInvariantString(stringValue);
                }

                return true;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error deserializing appSettings key {0}", key);
            }

            return false;
        }

        /// <summary>
        /// Get a value from configuration manager app settings
        /// </summary>
        /// <typeparam name="T">Type of value to get</typeparam>
        /// <param name="key">Key</param>
        /// <param name="value">Value to set</param>
        /// <param name="minValue">Min value</param>
        /// <param name="maxValue">Max value</param>
        /// <param name="clampSmallTimeSpan">Whether to clamp small timespan to max value</param>
        /// <returns>Value</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public void GetConfig<T>(string key, ref T value, T? minValue = null, T? maxValue = null, bool clampSmallTimeSpan = true) where T : struct, IComparable<T>
        {
            try
            {
                var stringValue = GetAppSettingsValue(key);
                if (!string.IsNullOrWhiteSpace(stringValue))
                {
                    var converter = TypeDescriptor.GetConverter(typeof(T));
                    value = (T)converter.ConvertFromInvariantString(stringValue);
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error deserializing appSettings key {0}", key);
            }

            if (minValue != null && maxValue != null)
            {
                value = value.Clamp(minValue.Value, maxValue.Value, clampSmallTimeSpan);
            }
        }

        /// <summary>
        /// Set a field / variable from configuration manager app settings. If null or not found, nothing is changed.
        /// </summary>
        /// <typeparam name="T">Type of value to set</typeparam>
        /// <param name="key">Key</param>
        /// <param name="value">Value</param>
        /// <param name="defaultValue">Default value if array was empty</param>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public void GetConfigArray<T>(string key, ref T[] value, T[] defaultValue)
        {
            try
            {
                var stringValue = GetAppSettingsValue(key) ?? string.Empty;
                var converter = TypeDescriptor.GetConverter(typeof(T));
                string[] items = stringValue.Split('|', ';', ',');
                List<T> list = new();
                foreach (string item in items)
                {
                    string normalizedItem = item.Trim();
                    if (normalizedItem.Length != 0)
                    {
                        list.Add((T)converter.ConvertFromInvariantString(normalizedItem));
                    }
                }
                if (list.Count == 0)
                {
                    value = (defaultValue ?? list.ToArray());
                }
                else
                {
                    value = list.ToArray();
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error deserializing appSettings key {0}", key);
            }
        }

        /// <summary>
        /// Load IPBan config from XML
        /// </summary>
        /// <param name="xml">XML string</param>
        /// <param name="dns">Dns lookup for resolving ip addresses, null for default</param>
        /// <param name="dnsList">Dns server list, null for none</param>
        /// <param name="httpRequestMaker">Http request maker, null for none</param>
        /// <returns>IPBanConfig</returns>
        public static IPBanConfig LoadFromXml(string xml, IDnsLookup dns = null, IDnsServerList dnsList = null,
            IHttpRequestMaker httpRequestMaker = null)
        {
            XmlDocument doc = new();
            doc.LoadXml(xml);
            return new IPBanConfig(doc, dns, dnsList, httpRequestMaker);
        }

        /// <summary>
        /// Load IPBan config from XML
        /// </summary>
        /// <param name="xml">XML document</param>
        /// <param name="dns">Dns lookup for resolving ip addresses, null for default</param>
        /// <param name="dnsList">Dns server list, null for none</param>
        /// <param name="httpRequestMaker">Http request maker, null for none</param>
        /// <returns>IPBanConfig</returns>
        public static IPBanConfig LoadFromXml(XmlDocument xml, IDnsLookup dns = null, IDnsServerList dnsList = null,
            IHttpRequestMaker httpRequestMaker = null)
        {
            return new IPBanConfig(xml, dns, dnsList, httpRequestMaker);
        }

        /// <summary>
        /// Check if a user name fails the user name whitelist regex. If the regex is empty, method returns false.
        /// </summary>
        /// <param name="userName">User name</param>
        /// <returns>True if failed the regex, false otherwise</returns>
        public bool UserNameFailsUserNameWhitelistRegex(string userName)
        {
            if (userNameWhitelistRegex is null)
            {
                return false;
            }
            userName = userName.Normalize().Trim();
            return !userNameWhitelistRegex.IsMatch(userName);
        }

        /// <summary>
        /// Checks if a user name is within the maximum edit distance for the user name whitelist.
        /// If the user name whitelist is empty, this method returns true.
        /// </summary>
        /// <param name="userName">User name</param>
        /// <param name="hasUserNameWhitelist">Whether a user name whitelist is defined</param>
        /// <returns>True if within max edit distance of any whitelisted user name, false otherwise.</returns>
        public bool IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(string userName, out bool hasUserNameWhitelist)
        {
            if (userNameWhitelist.Count == 0)
            {
                hasUserNameWhitelist = false;
                return false;
            }

            hasUserNameWhitelist = true;
            userName = userName.Normalize().ToUpperInvariant().Trim();
            foreach (string userNameToCheckAgainst in userNameWhitelist)
            {
                int distance = LevenshteinUnsafe.Distance(userName, userNameToCheckAgainst);
                if (distance <= userNameWhitelistMaximumEditDistance)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Return all the groups that match the specified keywords (Windows only)
        /// </summary>
        /// <param name="keywords">Keywords</param>
        /// <returns>Groups that match</returns>
        public IEnumerable<EventViewerExpressionGroup> WindowsEventViewerGetGroupsMatchingKeywords(ulong keywords)
        {
            if (WindowsEventViewerExpressionsToBlock is null && expressionsSuccess is null)
            {
                return Array.Empty<EventViewerExpressionGroup>();
            }
            else if (WindowsEventViewerExpressionsToBlock is null)
            {
                return expressionsSuccess.Groups.Where(g => (g.KeywordsULONG == keywords));
            }
            else if (expressionsSuccess is null)
            {
                return WindowsEventViewerExpressionsToBlock.Groups.Where(g => (g.KeywordsULONG == keywords));
            }
            return WindowsEventViewerExpressionsToBlock.Groups.Where(g => (g.KeywordsULONG == keywords))
                .Union(expressionsSuccess.Groups.Where(g => (g.KeywordsULONG == keywords)));
        }

        /// <summary>
        /// Change an app settings - no XML encoding is done, so ensure your key and new value are already encoded
        /// </summary>
        /// <param name="config">Entire XML config</param>
        /// <param name="key">App setting key to look for</param>
        /// <returns>The config value or null if not found</returns>
        public static string GetConfigAppSetting(string config, string key)
        {
            string find = $@"\<add key=""{key}"" value=""(?<value>[^""]*)"" *\/\>";
            Match match = Regex.Match(config, find, RegexOptions.IgnoreCase);
            return (match is null || !match.Success ? null : match.Groups["value"].Value);
        }

        /// <summary>
        /// Change an app settings - no XML encoding is done, so ensure your key and new value are already encoded
        /// </summary>
        /// <param name="config">Entire XML config</param>
        /// <param name="key">App setting key to look for</param>
        /// <param name="newValue">Replacement value</param>
        /// <returns>Modified config or the config passed in if not found</returns>
        public static string ChangeConfigAppSetting(string config, string key, string newValue)
        {
            newValue ??= string.Empty;

            XmlDocument doc = new();
            doc.LoadXml(config);
            XmlNode appSettings = doc.SelectSingleNode($"/configuration/appSettings");
            if (appSettings is null)
            {
                throw new InvalidOperationException("Unable to find appSettings in config");
            }
            XmlNode existingSetting = doc.SelectSingleNode($"/configuration/appSettings/add[@key='{key}']");
            if (existingSetting is null)
            {
                existingSetting = doc.CreateElement("add");
                XmlAttribute keyAttr = doc.CreateAttribute("key");
                keyAttr.Value = key;
                existingSetting.Attributes.Append(keyAttr);
                XmlAttribute valueAttr = doc.CreateAttribute("value");
                valueAttr.Value = newValue;
                existingSetting.Attributes.Append(valueAttr);
                appSettings.AppendChild(existingSetting);
            }
            else
            {
                existingSetting.Attributes["value"].Value = newValue;
            }
            return doc.OuterXml;
        }

        /// <summary>
        /// Merge two configurations
        /// </summary>
        /// <param name="xmlBase">Base configuration</param>
        /// <param name="xmlOverride">Override configuration</param>
        /// <returns>Merged configuration</returns>
        /// <exception cref="ArgumentException">Base xml is null or white space</exception>
        public static XmlDocument MergeXml(string xmlBase, string xmlOverride)
        {
            if (string.IsNullOrWhiteSpace(xmlBase))
            {
                throw new ArgumentException("Cannot merge null base xml");
            }

            XmlDocument docBase = new();
            docBase.LoadXml(xmlBase);

            if (string.IsNullOrWhiteSpace(xmlOverride))
            {
                return docBase;
            }

            XmlDocument docOverride = new();
            docOverride.LoadXml(xmlOverride);

            XmlNode logFilesOverride = docOverride.SelectSingleNode("/configuration/LogFilesToParse/LogFiles");
            XmlNode logFilesBase = docBase.SelectSingleNode("/configuration/LogFilesToParse/LogFiles") ?? logFilesOverride;
            if (logFilesBase is not null &&
                logFilesOverride is not null &&
                logFilesBase != logFilesOverride)
            {
                foreach (XmlNode overrideNode in logFilesOverride)
                {
                    if (overrideNode.NodeType == XmlNodeType.Element)
                    {
                        logFilesBase.AppendChild(docBase.ImportNode(overrideNode, true));
                    }
                }
            }

            XmlNode expressionsBlockOverride = docOverride.SelectSingleNode("/configuration/ExpressionsToBlock/Groups");
            XmlNode expressionsBlockBase = docBase.SelectSingleNode("/configuration/ExpressionsToBlock/Groups") ?? expressionsBlockOverride;
            if (expressionsBlockBase is not null &&
                expressionsBlockOverride is not null &&
                expressionsBlockBase != expressionsBlockOverride)
            {
                foreach (XmlNode overrideNode in expressionsBlockOverride)
                {
                    if (overrideNode.NodeType == XmlNodeType.Element)
                    {
                        expressionsBlockBase.AppendChild(docBase.ImportNode(overrideNode, true));
                    }
                }
            }

            XmlNode expressionsNotifyOverride = docOverride.SelectSingleNode("/configuration/ExpressionsToNotify/Groups");
            XmlNode expressionsNotifyBase = docBase.SelectSingleNode("/configuration/ExpressionsToNotify/Groups") ?? expressionsNotifyOverride;
            if (expressionsNotifyBase is not null &&
                expressionsNotifyOverride is not null &&
                expressionsNotifyBase != expressionsNotifyOverride)
            {
                foreach (XmlNode overrideNode in expressionsNotifyOverride)
                {
                    if (overrideNode.NodeType == XmlNodeType.Element)
                    {
                        expressionsNotifyBase.AppendChild(docBase.ImportNode(overrideNode, true));
                    }
                }
            }

            XmlNode appSettingsOverride = docOverride.SelectSingleNode("/configuration/appSettings");
            XmlNode appSettingsBase = docBase.SelectSingleNode("/configuration/appSettings") ?? appSettingsOverride;
            if (appSettingsBase is not null &&
                appSettingsOverride is not null &&
                appSettingsBase != appSettingsOverride)
            {
                foreach (XmlNode overrideNode in appSettingsOverride)
                {
                    if (overrideNode.NodeType == XmlNodeType.Element)
                    {
                        string xpath = $"/configuration/appSettings/add[@key='{overrideNode.Attributes["key"].Value}']";
                        XmlNode existing = appSettingsBase.SelectSingleNode(xpath);
                        if (existing is null)
                        {
                            // create a new node
                            appSettingsBase.AppendChild(docBase.ImportNode(overrideNode, true));
                        }
                        else
                        {
                            // replace existing node
                            string overrideValue = overrideNode.Attributes["value"]?.Value ?? string.Empty;
                            existing.Attributes["value"].Value = overrideValue;
                        }
                    }
                }
            }

            return docBase;
        }

        /// <inheritdoc />
        public bool IsWhitelisted(string entry) => whitelistFilter.IsFiltered(entry);

        /// <inheritdoc />
        public bool IsWhitelisted(IPAddressRange range) => whitelistFilter.IsFiltered(range);

        /// <summary>
        /// Raw xml
        /// </summary>
        public string Xml { get; }

        /// <summary>
        /// All app settings key/values
        /// </summary>
        public IReadOnlyDictionary<string, string> AppSettings => appSettings;

        /// <summary>
        /// Api key from https://ipthreat.net, if any
        /// </summary>
        public string IPThreatApiKey { get { return ipThreatApiKey; } }
        
        /// <summary>
        /// Number of failed login attempts before a ban is initiated
        /// </summary>
        public int FailedLoginAttemptsBeforeBan { get { return failedLoginAttemptsBeforeBan; } }

        /// <summary>
        /// Length of time to ban an ip address, each unban and reban moves to the next TimeSpan in the array, until the last which then
        /// drops the ip address out of the ban list and starts over at the first TimeSpan in the array.
        /// This array will always have at least one value.
        /// </summary>
        public TimeSpan[] BanTimes { get { return banTimes; } }

        /// <summary>
        /// Whether to reset failed login count to 0 when an ip address is unbanned and using multiple BanTimes
        /// </summary>
        public bool ResetFailedLoginCountForUnbannedIPAddresses { get { return resetFailedLoginCountForUnbannedIPAddresses; } }

        /// <summary>
        /// The duration after the last failed login attempt that the count is reset back to 0.
        /// </summary>
        public TimeSpan ExpireTime { get { return expireTime; } }

        /// <summary>
        /// Interval of time to do house-keeping chores like un-banning ip addresses
        /// </summary>
        public TimeSpan CycleTime { get { return cycleTime; } }

        /// <summary>
        /// The minimum time between failed login attempts to increment the ban counter
        /// </summary>
        public TimeSpan MinimumTimeBetweenFailedLoginAttempts { get { return minimumTimeBetweenFailedLoginAttempts; } }

        /// <summary>
        /// The minimum time between successful login attempts to increment the success counter
        /// </summary>
        public TimeSpan MinimumTimeBetweenSuccessfulLoginAttempts { get { return minimumTimeBetweenSuccessfulLoginAttempts; } }

        /// <summary>
        /// Rule prefix for firewall
        /// </summary>
        public string FirewallRulePrefix { get { return firewallRulePrefix; } }

        /// <summary>
        /// Event viewer expressions to block (Windows only)
        /// </summary>
        public EventViewerExpressionsToBlock WindowsEventViewerExpressionsToBlock { get { return expressionsFailure; } }

        /// <summary>
        /// Event viewer expressions to notify for successful logins (Windows only)
        /// </summary>
        public EventViewerExpressionsToNotify WindowsEventViewerExpressionsToNotify { get { return expressionsSuccess; } }

        /// <summary>
        /// Log files to parse
        /// </summary>
        public IReadOnlyList<IPBanLogFileToParse> LogFilesToParse { get { return logFiles; } }

        /// <summary>
        /// True to clear and unban ip addresses upon restart, false otherwise
        /// </summary>
        public bool ClearBannedIPAddressesOnRestart { get { return clearBannedIPAddressesOnRestart; } }

        /// <summary>
        /// Whether to clear failed logins when an ip has a successful login (default false)
        /// </summary>
        public bool ClearFailedLoginsOnSuccessfulLogin { get { return clearFailedLoginsOnSuccessfulLogin; } }

        /// <summary>
        /// Whether to process internal ip addresses (default false)
        /// </summary>
        public bool ProcessInternalIPAddresses { get { return processInternalIPAddresses; } }

        /// <summary>
        /// Whitelist
        /// </summary>
        public IIPBanFilter WhitelistFilter => whitelistFilter;

        /// <summary>
        /// Blacklist
        /// </summary>
        public IIPBanFilter BlacklistFilter => blacklistFilter;

        /// <summary>
        /// Characters to truncate user names at, empty for no truncation
        /// </summary>
        public string TruncateUserNameChars { get { return truncateUserNameChars; } }

        /// <summary>
        /// White list user names. Any user name found not in the list is banned, unless the list is empty, in which case no checking is done.
        /// If not empty, Any user name within 'UserNameWhitelistMinimumEditDistance' in the config is also not banned.
        /// </summary>
        public IReadOnlyCollection<string> UserNameWhitelist { get { return userNameWhitelist; } }

        /// <summary>
        /// User name whitelist regex, or empty if not set.
        /// </summary>
        public string UserNameWhitelistRegex { get { return (userNameWhitelistRegex is null ? string.Empty : userNameWhitelistRegex.ToString()); } }

        /// <summary>
        /// Number of failed logins before banning a user name in the user name whitelist
        /// </summary>
        public int FailedLoginAttemptsBeforeBanUserNameWhitelist { get { return failedLoginAttemptsBeforeBanUserNameWhitelist; } }

        /// <summary>
        /// Process to run on ban. See ReplaceUrl in IPBanService.cs for place-holders.
        /// </summary>
        public string ProcessToRunOnBan { get { return processToRunOnBan; } }

        /// <summary>
        /// Process to run on unban. See ReplaceUrl in IPBanService.cs for place-holders.
        /// </summary>
        public string ProcessToRunOnUnban { get { return processToRunOnUnban; } }

        /// <summary>
        /// Whether to use the default banned ip address handler
        /// </summary>
        public bool UseDefaultBannedIPAddressHandler { get { return useDefaultBannedIPAddressHandler; } }

        /// <summary>
        /// List of extra block rules to create
        /// </summary>
        public IReadOnlyList<IPBanFirewallRule> ExtraRules { get { return extraRules; } }

        /// <summary>
        /// Config entry for firewall uri rules, one per line. Format is RulePrefix,Interval(DD:HH:MM:SS),Uri[NEWLINE]
        /// </summary>
        public string FirewallUriRules { get { return firewallUriRules; } }

        /// <summary>
        /// A url to get when the service updates, empty for none. See ReplaceUrl of IPBanService for place-holders.
        /// </summary>
        public string GetUrlUpdate { get { return getUrlUpdate; } }

        /// <summary>
        /// A url to get when the service starts, empty for none. See ReplaceUrl of IPBanService for place-holders.
        /// </summary>
        public string GetUrlStart { get { return getUrlStart; } }

        /// <summary>
        /// A url to get when the service stops, empty for none. See ReplaceUrl of IPBanService for place-holders.
        /// </summary>
        public string GetUrlStop { get { return getUrlStop; } }

        /// <summary>
        /// A url to get for a config file update, empty for none. See ReplaceUrl of IPBanService for place-holders.
        /// </summary>
        public string GetUrlConfig { get { return getUrlConfig; } }
    }
}
