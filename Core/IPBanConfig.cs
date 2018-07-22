#region Imports

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

#endregion Imports

namespace IPBan
{
    /// <summary>
    /// Configuration for ip ban app
    /// </summary>
    public class IPBanConfig
    {
        private ExpressionsToBlock expressions;
        private Regex whiteListRegex;
        private Regex blackListRegex;

        private readonly LogFileToParse[] logFiles;
        private readonly TimeSpan banTime = TimeSpan.FromDays(1.0d);
        private readonly TimeSpan expireTime = TimeSpan.FromDays(1.0d);
        private readonly TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private readonly TimeSpan minimumTimeBetweenFailedLoginAttempts = TimeSpan.FromSeconds(5.0);
        private readonly int failedLoginAttemptsBeforeBan = 5;
        private readonly string ruleName = "BlockIPAddresses";
        private readonly HashSet<string> blackList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> whiteList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly bool clearBannedIPAddressesOnRestart;
        private readonly HashSet<string> userNameWhitelist = new HashSet<string>(StringComparer.Ordinal);
        private readonly int userNameWhitelistMaximumEditDistance = 2;
        private readonly int failedLoginAttemptsBeforeBanUserNameWhitelist = 20;
        private readonly string processToRunOnBan;
        private readonly string getUrlUpdate;
        private readonly string getUrlStart;
        private readonly string getUrlStop;
        private readonly string getUrlConfig;
        private readonly string externalIPAddressUrl;

        private void PopulateList(HashSet<string> set, ref Regex regex, string setValue, string regexValue)
        {
            setValue = (setValue ?? string.Empty).Trim();
            regexValue = (regexValue ?? string.Empty).Replace("*", @"[0-9A-Fa-f]+?").Trim();
            set.Clear();
            regex = null;

            if (!string.IsNullOrWhiteSpace(setValue))
            {
                foreach (string v in setValue.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string ipOrDns = v.Trim();
                    if (ipOrDns != "0.0.0.0" && ipOrDns != "::0" && ipOrDns != "127.0.0.1" && ipOrDns != "::1")
                    {
                        try
                        {
                            if (IPAddressRange.TryParse(ipOrDns, out _))
                            {
                                set.Add(ipOrDns);
                            }
                            else
                            {
                                IPAddress[] addresses = Dns.GetHostEntry(ipOrDns).AddressList;
                                if (addresses != null)
                                {
                                    foreach (IPAddress adr in addresses)
                                    {
                                        set.Add(adr.ToString());
                                    }
                                }
                            }
                        }
                        catch (System.Net.Sockets.SocketException)
                        {
                            // ignore, dns lookup fails
                        }
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(regexValue))
            {
                regex = new Regex(regexValue, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
            }
        }

        /// <summary>
        /// Get a value from configuration manager app settings
        /// </summary>
        /// <typeparam name="T">Type of value to get</typeparam>
        /// <param name="key">Key</param>
        /// <param name="defaultValue">Default value if null or not found</param>
        /// <returns>Value</returns>
        public static T GetConfig<T>(string key, T defaultValue = default)
        {
            try
            {
                var converter = TypeDescriptor.GetConverter(typeof(T));
                return (T)converter.ConvertFromInvariantString(ConfigurationManager.AppSettings[key]);
            }
            catch
            {
                return defaultValue;
            }
        }

        /// <summary>
        /// Set a field / variable from configuration manager app settings. If null or not found, nothing is changed.
        /// </summary>
        /// <typeparam name="T">Type of value to set</typeparam>
        /// <param name="key">Key</param>
        /// <param name="value">Value</param>
        public static void SetConfig<T>(string key, ref T value)
        {
            try
            {
                var converter = TypeDescriptor.GetConverter(typeof(T));
                value = (T)converter.ConvertFromInvariantString(ConfigurationManager.AppSettings[key]);
            }
            catch
            {
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        public IPBanConfig(string configFilePath)
        {
            configFilePath = (configFilePath ?? ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath);
            if (configFilePath != ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath)
            {
                File.Copy(configFilePath, ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath, true);
            }

            ConfigurationManager.RefreshSection("appSettings");
            ConfigurationManager.RefreshSection("configSections");
            ConfigurationManager.RefreshSection("nlog");
            ConfigurationManager.RefreshSection("ExpressionsToBlock");
            ConfigurationManager.RefreshSection("LogFilesToParse");

            SetConfig<int>("FailedLoginAttemptsBeforeBan", ref failedLoginAttemptsBeforeBan);
            SetConfig<TimeSpan>("BanTime", ref banTime);
            SetConfig<bool>("ClearBannedIPAddressesOnRestart", ref clearBannedIPAddressesOnRestart);
            SetConfig<TimeSpan>("ExpireTime", ref expireTime);
            SetConfig<TimeSpan>("CycleTime", ref cycleTime);
            SetConfig<TimeSpan>("MinimumTimeBetweenFailedLoginAttempts", ref minimumTimeBetweenFailedLoginAttempts);
            SetConfig<string>("RuleName", ref ruleName);

            string whiteListString = GetConfig<string>("Whitelist", string.Empty);
            string whiteListRegexString = GetConfig<string>("WhitelistRegex", string.Empty);
            string blacklistString = GetConfig<string>("Blacklist", string.Empty);
            string blacklistRegexString = GetConfig<string>("BlacklistRegex", string.Empty);
            PopulateList(whiteList, ref whiteListRegex, whiteListString, whiteListRegexString);
            PopulateList(blackList, ref blackListRegex, blacklistString, blacklistRegexString);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                expressions = (ExpressionsToBlock)System.Configuration.ConfigurationManager.GetSection("ExpressionsToBlock");
                if (expressions != null)
                {
                    foreach (ExpressionsToBlockGroup group in expressions.Groups)
                    {
                        foreach (ExpressionToBlock expression in group.Expressions)
                        {
                            expression.Regex = (expression.Regex ?? string.Empty).Trim();
                            if (expression.Regex.Length != 0)
                            {
                                if (expression.Regex[0] == '^')
                                {
                                    expression.Regex = "^\\s*?" + expression.Regex.Substring(1) + "\\s*?";
                                }
                                else
                                {
                                    expression.Regex = "\\s*?" + expression.Regex + "\\s*?";
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                expressions = new ExpressionsToBlock { Groups = new ExpressionsToBlockGroup[0] };
            }
            logFiles = ((LogFilesToParse)System.Configuration.ConfigurationManager.GetSection("LogFilesToParse"))?.LogFiles ?? new LogFileToParse[0];
            SetConfig<string>("ProcessToRunOnBan", ref processToRunOnBan);
            string userNameWhiteListString = GetConfig<string>("UserNameWhiteList", string.Empty);
            foreach (string userName in userNameWhiteListString.Split(','))
            {
                string userNameTrimmed = userName.Normalize().Trim();
                if (userNameTrimmed.Length > 0)
                {
                    userNameWhitelist.Add(userNameTrimmed);
                }
            }
            SetConfig<int>("UserNameWhiteListMinimumEditDistance", ref userNameWhitelistMaximumEditDistance);
            SetConfig<int>("FailedLoginAttemptsBeforeBanUserNameWhitelist", ref failedLoginAttemptsBeforeBanUserNameWhitelist);
            SetConfig<string>("GetUrlUpdate", ref getUrlUpdate);
            SetConfig<string>("GetUrlStart", ref getUrlStart);
            SetConfig<string>("GetUrlStop", ref getUrlStop);
            SetConfig<string>("GetUrlConfig", ref getUrlConfig);
            SetConfig<string>("ExternalIPAddressUrl", ref externalIPAddressUrl);
        }

        /// <summary>
        /// Check if an ip address is whitelisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        public bool IsIPAddressWhitelisted(string ipAddress)
        {
            return !string.IsNullOrWhiteSpace(ipAddress) &&
                (whiteList.Contains(ipAddress) ||
                !IPAddress.TryParse(ipAddress, out IPAddress ip) ||
                (whiteListRegex != null && whiteListRegex.IsMatch(ipAddress)));
        }

        /// <summary>
        /// Check if an ip address, dns name or user name is blacklisted
        /// </summary>
        /// <param name="ipAddressDnsOrUserName">IP address, dns name or user name</param>
        /// <returns>True if blacklisted, false otherwise</returns>
        public bool IsBlackListed(string ipAddressDnsOrUserName)
        {
            return !string.IsNullOrWhiteSpace(ipAddressDnsOrUserName) &&
                ((blackList.Contains(ipAddressDnsOrUserName) ||
                (blackListRegex != null && blackListRegex.IsMatch(ipAddressDnsOrUserName))));
        }

        /// <summary>
        /// Check if a user name is whitelisted
        /// </summary>
        /// <param name="userName">User name</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        public bool IsUserNameWhitelisted(string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                return false;
            }
            userName = userName.ToUpperInvariant().Normalize();
            return userNameWhitelist.Contains(userName);
        }

        /// <summary>
        /// Checks if a user name is within the maximum edit distance for the user name whitelist.
        /// If userName is null or empty this method returns true.
        /// If the user name whitelist is empty, this method returns true.
        /// </summary>
        /// <param name="userName">User name</param>
        /// <returns>True if within max edit distance of any whitelisted user name, false otherwise.</returns>
        public bool IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(string userName)
        {
            if (userNameWhitelist.Count == 0 || string.IsNullOrEmpty(userName))
            {
                return true;
            }

            userName = userName.ToUpperInvariant().Normalize();
            foreach (string userNameInWhitelist in userNameWhitelist)
            {
                int distance = LevenshteinUnsafe.Distance(userName, userNameInWhitelist);
                if (distance <= userNameWhitelistMaximumEditDistance)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Return all the groups that match the specified keywords
        /// </summary>
        /// <param name="keywords">Keywords</param>
        /// <returns>Groups that match</returns>
        public IEnumerable<ExpressionsToBlockGroup> GetGroupsMatchingKeywords(ulong keywords)
        {
            return WindowsEventViewerExpressionsToBlock.Groups.Where(g => (g.KeywordsULONG == keywords));
        }

        /// <summary>
        /// Number of failed login attempts before a ban is initiated
        /// </summary>
        public int FailedLoginAttemptsBeforeBan { get { return failedLoginAttemptsBeforeBan; } }

        /// <summary>
        /// Length of time to ban an ip address
        /// </summary>
        public TimeSpan BanTime { get { return banTime; } }

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
        /// Rule name for Windows Firewall
        /// </summary>
        public string RuleName { get { return ruleName; } }

        /// <summary>
        /// Event viewer expressions to block (Windows only)
        /// </summary>
        public ExpressionsToBlock WindowsEventViewerExpressionsToBlock { get { return expressions; } }

        /// <summary>
        /// Log files to parse
        /// </summary>
        public IReadOnlyCollection<LogFileToParse> LogFilesToParse { get { return logFiles; } }

        /// <summary>
        /// True to clear and unban ip addresses upon restart, false otherwise
        /// </summary>
        public bool ClearBannedIPAddressesOnRestart { get { return clearBannedIPAddressesOnRestart; } }

        /// <summary>
        /// Black list of ips as a comma separated string
        /// </summary>
        public string BlackList { get { return string.Join(",", blackList); } }

        /// <summary>
        /// Black list regex
        /// </summary>
        public string BlackListRegex { get { return (blackListRegex == null ? string.Empty : blackListRegex.ToString()); } }

        /// <summary>
        /// White list of ips as a comma separated string
        /// </summary>
        public string WhiteList { get { return string.Join(",", whiteList); } }

        /// <summary>
        /// White list regex
        /// </summary>
        public string WhiteListRegex { get { return (whiteListRegex == null ? string.Empty : whiteListRegex.ToString()); } }

        /// <summary>
        /// White list user names. Any user name found not in the list is banned.
        /// </summary>
        public IReadOnlyCollection<string> UserNameWhitelist { get { return userNameWhitelist; } }

        /// <summary>
        /// Number of failed logins before banning a user name in the user name whitelist
        /// </summary>
        public int FailedLoginAttemptsBeforeBanUserNameWhitelist { get { return failedLoginAttemptsBeforeBanUserNameWhitelist; } }

        /// <summary>
        /// Process to run on ban - replace ###IPADDRESS### with the banned ip address
        /// </summary>
        public string ProcessToRunOnBan { get { return processToRunOnBan; } }

        /// <summary>
        /// A url to get when the service updates, empty for none. ###IPADDRESS### will be replaced with the local ip. ###MACHINENAME### will be replaced with the fully qualified domain name of the machine.
        /// </summary>
        public string GetUrlUpdate { get { return getUrlUpdate; } }

        /// <summary>
        /// A url to get when the service starts, empty for none. ###IPADDRESS### will be replaced with the local ip. ###MACHINENAME### will be replaced with the fully qualified domain name of the machine.
        /// </summary>
        public string GetUrlStart { get { return getUrlStart; } }

        /// <summary>
        /// A url to get when the service stops, empty for none. ###IPADDRESS### will be replaced with the local ip. ###MACHINENAME### will be replaced with the fully qualified domain name of the machine.
        /// </summary>
        public string GetUrlStop { get { return getUrlStop; } }

        /// <summary>
        /// A url to get for a config file update, empty for none. ###IPADDRESS### will be replaced with the local ip. ###MACHINENAME### will be replaced with the fully qualified domain name of the machine.
        /// </summary>
        public string GetUrlConfig { get { return getUrlConfig; } }

        /// <summary>
        /// Url to query to get the external ip address, the url should return a string which is the external ip address.
        /// </summary>
        public string ExternalIPAddressUrl { get { return externalIPAddressUrl; } }
    }
}
