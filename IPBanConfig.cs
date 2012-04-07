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
        private TimeSpan cycleTime = TimeSpan.FromMinutes(1.0d);
        private string ruleName = "BlockIPAddresses";
        private readonly HashSet<string> whiteList = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private Regex whiteListRegex;

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

            value = ConfigurationManager.AppSettings["CycleTime"];
            cycleTime = TimeSpan.Parse(value);

            value = ConfigurationManager.AppSettings["RuleName"];
            ruleName = value;

            value = ConfigurationManager.AppSettings["Whitelist"];
            whiteList.Clear();
            if (!string.IsNullOrWhiteSpace(value))
            {
                foreach (string ip in value.Split(','))
                {
                    whiteList.Add(ip.Trim());
                }
            }

            value = (ConfigurationManager.AppSettings["WhitelistRegex"] ?? string.Empty).Replace("*", "[0-255]").Trim();
            if (value.Length != 0)
            {
                whiteListRegex = new Regex(value, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline);
            }

            expressions = (ExpressionsToBlock)System.Configuration.ConfigurationManager.GetSection("ExpressionsToBlock");
        }

        /// <summary>
        /// Check if an ip address is whitelisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if white listed, false otherwise</returns>
        public bool IsWhiteListed(string ipAddress)
        {
            IPAddress ip;

            return (whiteList.Contains(ipAddress) || !IPAddress.TryParse(ipAddress, out ip) || (whiteListRegex != null && whiteListRegex.IsMatch(ipAddress)));
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
    }
}
