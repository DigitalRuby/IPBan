#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
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
        private TimeSpan banTime = TimeSpan.FromDays(1.0d);
        private TimeSpan expireTime = TimeSpan.FromDays(1.0d);
        private TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private TimeSpan minimumTimeBetweenFailedLoginAttempts = TimeSpan.FromSeconds(5.0);
        private Regex whiteListRegex;
        private Regex blackListRegex;

        private readonly int failedLoginAttemptsBeforeBan = 5;
        private readonly string ruleName = "BlockIPAddresses";
        private readonly HashSet<string> blackList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> whiteList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly bool clearBannedIPAddressesOnRestart;
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
                    set.Add(v.Trim());

                    if (v != "0.0.0.0" && v != "::0" && IPAddress.TryParse(v, out IPAddress tmp))
                    {
                        try
                        {
                            IPAddress[] addresses = Dns.GetHostEntry(v).AddressList;
                            if (addresses != null)
                            {
                                foreach (IPAddress adr in addresses)
                                {
                                    set.Add(adr.ToString());
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

            if (regexValue.Length != 0)
            {
                regex = new Regex(regexValue, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configFilePath">Config file path</param>
        public IPBanConfig(string configFilePath)
        {
            if (configFilePath != AppDomain.CurrentDomain.SetupInformation.ConfigurationFile)
            {
                File.Copy(configFilePath, AppDomain.CurrentDomain.SetupInformation.ConfigurationFile, true);
            }

            ConfigurationManager.RefreshSection("appSettings");
            ConfigurationManager.RefreshSection("configSections");
            ConfigurationManager.RefreshSection("nlog");
            ConfigurationManager.RefreshSection("ExpressionsToBlock");

            string value = ConfigurationManager.AppSettings["FailedLoginAttemptsBeforeBan"];
            failedLoginAttemptsBeforeBan = int.Parse(value, CultureInfo.InvariantCulture);

            value = ConfigurationManager.AppSettings["BanTime"];
            banTime = TimeSpan.Parse(value, CultureInfo.InvariantCulture);

            value = ConfigurationManager.AppSettings["ClearBannedIPAddressesOnRestart"];
            bool.TryParse(value, out clearBannedIPAddressesOnRestart);

            value = ConfigurationManager.AppSettings["ExpireTime"];
            expireTime = TimeSpan.Parse(value, CultureInfo.InvariantCulture);
            
            value = ConfigurationManager.AppSettings["CycleTime"];
            cycleTime = TimeSpan.Parse(value, CultureInfo.InvariantCulture);

            value = ConfigurationManager.AppSettings["MinimumTimeBetweenFailedLoginAttempts"];
            minimumTimeBetweenFailedLoginAttempts = TimeSpan.Parse(value, CultureInfo.InvariantCulture);

            value = ConfigurationManager.AppSettings["RuleName"];
            ruleName = value;

            PopulateList(whiteList, ref whiteListRegex, ConfigurationManager.AppSettings["Whitelist"], ConfigurationManager.AppSettings["WhitelistRegex"]);
            PopulateList(blackList, ref blackListRegex, ConfigurationManager.AppSettings["Blacklist"], ConfigurationManager.AppSettings["BlacklistRegex"]);
            expressions = (ExpressionsToBlock)System.Configuration.ConfigurationManager.GetSection("ExpressionsToBlock");

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
                    expression.RegexObject = new Regex(expression.Regex, RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled);
                }
            }

            processToRunOnBan = ConfigurationManager.AppSettings["ProcessToRunOnBan"];
            getUrlUpdate = ConfigurationManager.AppSettings["GetUrlUpdate"];
            getUrlStart = ConfigurationManager.AppSettings["GetUrlStart"];
            getUrlStop = ConfigurationManager.AppSettings["GetUrlStop"];
            getUrlConfig = ConfigurationManager.AppSettings["GetUrlConfig"];
            externalIPAddressUrl = ConfigurationManager.AppSettings["ExternalIPAddressUrl"];
        }

        /// <summary>
        /// Check if an ip address is whitelisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        public bool IsWhiteListed(string ipAddress)
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
        /// Return all the groups that match the specified keywords
        /// </summary>
        /// <param name="keywords">Keywords</param>
        /// <returns>Groups that match</returns>
        public IEnumerable<ExpressionsToBlockGroup> GetGroupsMatchingKeywords(ulong keywords)
        {
            return Expressions.Groups.Where(g => (g.KeywordsULONG == keywords));
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
        /// Expressions to block
        /// </summary>
        public ExpressionsToBlock Expressions { get { return expressions; } }

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
