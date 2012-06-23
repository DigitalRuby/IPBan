#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
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
        private int failedLoginAttemptsBeforeBan = 5;
        private TimeSpan banTime = TimeSpan.FromDays(1.0d);
        private string banFile = "banlog.txt";
        private TimeSpan expireTime = TimeSpan.FromDays(1.0d);
        private TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private string ruleName = "BlockIPAddresses";
        private readonly HashSet<string> whiteList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private Regex whiteListRegex;
        private readonly HashSet<string> blackList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private Regex blackListRegex;
        private bool banFileClearOnRestart;

        private void PopulateList(HashSet<string> set, ref Regex regex, string setValue, string regexValue)
        {
            setValue = (setValue ?? string.Empty).Trim();
            regexValue = (regexValue ?? string.Empty).Replace("*", "[0-255]").Trim();
            set.Clear();

            if (!string.IsNullOrWhiteSpace(setValue))
            {
                IPAddress tmp;

                foreach (string ip in setValue.Split(','))
                {
                    if (ip.Length <= 2 || IPAddress.TryParse(ip, out tmp))
                    {
                        set.Add(ip.Trim());
                    }
                    else
                    {
                        try
                        {
                            IPAddress[] addresses = Dns.GetHostEntry(ip).AddressList;
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
                            set.Add(ip.Trim());
                        }
                    }
                }
            }

            if (regexValue.Length != 0)
            {
                regex = new Regex(regexValue, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public IPBanConfig()
        {
            string value = ConfigurationManager.AppSettings["FailedLoginAttemptsBeforeBan"];
            failedLoginAttemptsBeforeBan = int.Parse(value);

            value = ConfigurationManager.AppSettings["BanTime"];
            banTime = TimeSpan.Parse(value);

            value = ConfigurationManager.AppSettings["BanFile"];
            banFile = value;
            if (!Path.IsPathRooted(banFile))
            {
                banFile = Path.GetFullPath(banFile);
            }
            value = ConfigurationManager.AppSettings["BanFileClearOnRestart"];
            if (!bool.TryParse(value, out banFileClearOnRestart))
            {
                banFileClearOnRestart = true;
            }

            value = ConfigurationManager.AppSettings["ExpireTime"];
            expireTime = TimeSpan.Parse(value);
            
            value = ConfigurationManager.AppSettings["CycleTime"];
            cycleTime = TimeSpan.Parse(value);

            value = ConfigurationManager.AppSettings["RuleName"];
            ruleName = value;

            PopulateList(whiteList, ref whiteListRegex, ConfigurationManager.AppSettings["Whitelist"], ConfigurationManager.AppSettings["WhitelistRegex"]);
            PopulateList(blackList, ref blackListRegex, ConfigurationManager.AppSettings["Blacklist"], ConfigurationManager.AppSettings["BlacklistRegex"]);
            expressions = (ExpressionsToBlock)System.Configuration.ConfigurationManager.GetSection("ExpressionsToBlock");
        }

        /// <summary>
        /// Check if an ip address is whitelisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        public bool IsWhiteListed(string ipAddress)
        {
            IPAddress ip;

            return (whiteList.Contains(ipAddress) || !IPAddress.TryParse(ipAddress, out ip) || (whiteListRegex != null && whiteListRegex.IsMatch(ipAddress)));
        }

        /// <summary>
        /// Check if an ip address is blacklisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if blacklisted, false otherwise</returns>
        public bool IsBlackListed(string ipAddress)
        {
            return (blackList.Contains(ipAddress) || (blackListRegex != null && blackListRegex.IsMatch(ipAddress)));
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
        /// Ban file
        /// </summary>
        public string BanFile { get { return banFile; } }

        /// <summary>
        /// The duration after the last failed login attempt that the count is reset back to 0.
        /// </summary>
        public TimeSpan ExpireTime { get { return expireTime; } }
        
        /// <summary>
        /// Interval of time to do house-keeping chores like un-banning ip addresses
        /// </summary>
        public TimeSpan CycleTime { get { return cycleTime; } }

        /// <summary>
        /// Rule name for Windows Firewall
        /// </summary>
        public string RuleName { get { return ruleName; } }

        /// <summary>
        /// Expressions to block
        /// </summary>
        public ExpressionsToBlock Expressions { get { return expressions; } }

        /// <summary>
        /// True to clear and unband ip addresses in the ban file when the service restarts, false otherwise
        /// </summary>
        public bool BanFileClearOnRestart { get { return banFileClearOnRestart; } }
    }
}
