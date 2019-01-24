#region Imports

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Configuration;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.Security.Cryptography;
using System.Web;

#endregion Imports

namespace IPBan
{
    public class IPBanService : IIPBanService
    {
        private enum UrlType
        {
            Start,
            Update,
            Stop,
            Config
        }

        private class FailedLogin
        {
            public string IPAddress { get; set; }
            public string UserName { get; set; }
            public DateTime DateTime { get; set; }
            public int Count { get; set; }
            public string Source { get; set; }
        }

        private System.Timers.Timer cycleTimer;
        private bool firewallNeedsBlockedIPAddressesUpdate;
        private bool gotStartUrl;

        // note that an ip that has a block count may not yet be in the ipAddressesAndBanDate dictionary
        // for locking, always use ipAddressesAndBanDate
        private readonly IPBanDB ipDB = new IPBanDB();
        private readonly object configLock = new object();
        private readonly HashSet<IUpdater> updaters = new HashSet<IUpdater>();
        private readonly HashSet<IPBanLogFileScanner> logFilesToParse = new HashSet<IPBanLogFileScanner>();

        private HashSet<string> ipAddressesToAllowInFirewall = new HashSet<string>();
        private bool ipAddressesToAllowInFirewallNeedsUpdate;
        private DateTime lastConfigFileDateTime = DateTime.MinValue;

        // the windows event viewer calls back on a background thread, this allows pushing the ip addresses to a list that will be accessed
        //  in the main loop
        private readonly List<FailedLogin> pendingFailedLogins = new List<FailedLogin>();

        private void RunTask(Action action)
        {
            if (MultiThreaded)
            {
                System.Threading.Tasks.Task.Run(action);
            }
            else
            {
                action.Invoke();
            }
        }

        private void UpdateLogFiles(IPBanConfig newConfig)
        {
            // remove existing log files that are no longer in config
            foreach (IPBanLogFileScanner file in logFilesToParse.ToArray())
            {
                if (newConfig.LogFilesToParse.FirstOrDefault(f => f.PathAndMask.Split('\n').Contains(file.PathAndMask)) == null)
                {
                    file.Dispose();
                    logFilesToParse.Remove(file);
                }
            }
            foreach (LogFileToParse newFile in newConfig.LogFilesToParse)
            {
                string[] pathsAndMasks = newFile.PathAndMask.Split('\n');
                for (int i = 0; i < pathsAndMasks.Length; i++)
                {
                    string pathAndMask = pathsAndMasks[i].Trim();
                    if (pathAndMask.Length != 0)
                    {
                        // if we don't have this log file and the platform matches, add it
                        if (logFilesToParse.FirstOrDefault(f => f.PathAndMask == pathAndMask) == null &&
                            !string.IsNullOrWhiteSpace(newFile.PlatformRegex) &&
                            Regex.IsMatch(IPBanOS.Description, newFile.PlatformRegex.Trim(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                        {
                            // log files use a timer internally and do not need to be updated regularly
                            IPBanLogFileScanner scanner = new IPBanLogFileScanner(this, DnsLookup,
                                newFile.Source, pathAndMask, newFile.Recursive, newFile.Regex, newFile.MaxFileSize, newFile.PingInterval);
                            logFilesToParse.Add(scanner);
                        }
                        else
                        {
                            IPBanLog.Debug("Ignoring log file {0}", newFile);
                        }
                    }
                }
            }
        }

        internal void ReadAppSettings()
        {
            try
            {
                ConfigFilePath = (string.IsNullOrWhiteSpace(ConfigFilePath) ? ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath : ConfigFilePath);
                DateTime lastDateTime = File.GetLastWriteTimeUtc(ConfigFilePath);
                if (lastDateTime > lastConfigFileDateTime)
                {
                    lastConfigFileDateTime = lastDateTime;
                    lock (configLock)
                    {
                        IPBanConfig newConfig = IPBanConfig.LoadFromFile(ConfigFilePath, DnsLookup);
                        UpdateLogFiles(newConfig);
                        Config = newConfig;
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);

                if (Config == null)
                {
                    throw new ApplicationException("Configuration failed to load, make sure to unblock all the files. Right click each file, select properties and then unblock.", ex);
                }
            }
        }

        private void SetNetworkInfo()
        {
            if (string.IsNullOrWhiteSpace(FQDN))
            {
                string serverName = System.Environment.MachineName;
                try
                {
                    FQDN = System.Net.Dns.GetHostEntry(serverName).HostName;
                }
                catch
                {
                    FQDN = serverName;
                }
            }

            if (string.IsNullOrWhiteSpace(LocalIPAddressString))
            {
                try
                {
                    // append ipv4 first, then the ipv6 then the remote ip
                    IPAddress[] ips = DnsLookup.GetHostAddressesAsync(Dns.GetHostName()).Sync();
                    foreach (IPAddress ip in ips)
                    {
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            LocalIPAddressString = ip.ToString();
                            break;
                        }
                    }
                    if (string.IsNullOrWhiteSpace(LocalIPAddressString))
                    {
                        foreach (IPAddress ip in ips)
                        {
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                            {
                                LocalIPAddressString = ip.ToString();
                                break;
                            }
                        }
                    }
                }
                catch
                {

                }
            }

            if (string.IsNullOrWhiteSpace(RemoteIPAddressString))
            {
                try
                {
                    RemoteIPAddressString = this.ExternalIPAddressLookup.LookupExternalIPAddressAsync(RequestMaker, Config.ExternalIPAddressUrl).Sync().ToString();
                    IPBanLog.Info("Remote ip address: {0}", RemoteIPAddressString);
                }
                catch
                {

                }
            }

            // hit start url if first time, if not first time will be ignored
            GetUrl(UrlType.Start);

            // send update
            GetUrl(UrlType.Update);

            // request new config file
            GetUrl(UrlType.Config);
        }

        private void LogInitialConfig()
        {
            IPBanLog.Info("Whitelist: {0}, Whitelist Regex: {1}", Config.WhiteList, Config.WhiteListRegex);
            IPBanLog.Info("Blacklist: {0}, Blacklist Regex: {1}", Config.BlackList, Config.BlackListRegex);
        }

        private void ProcessPendingFailedLogins(IEnumerable<FailedLogin> ipAddresses)
        {
            List<KeyValuePair<string, string>> bannedIpAddresses = new List<KeyValuePair<string, string>>();
            foreach (FailedLogin failedLogin in ipAddresses)
            {
                try
                {
                    string ipAddress = failedLogin.IPAddress;
                    string userName = failedLogin.UserName;
                    string source = failedLogin.Source;
                    if (Config.IsIPAddressWhitelisted(ipAddress) ||
                        (IPBanDelegate != null && IPBanDelegate.IsIPAddressWhitelisted(ipAddress)))
                    {
                        IPBanLog.Warn("Ignoring whitelisted ip address {0}, {1}, {2}", ipAddress, userName, source);
                    }
                    else
                    {
                        int maxFailedLoginAttempts;
                        if (Config.IsUserNameWhitelisted(userName))
                        {
                            maxFailedLoginAttempts = Config.FailedLoginAttemptsBeforeBanUserNameWhitelist;
                        }
                        else
                        {
                            maxFailedLoginAttempts = Config.FailedLoginAttemptsBeforeBan;
                        }

                        DateTime now = failedLogin.DateTime;

                        // check for the target user name for additional blacklisting checks                    
                        bool configBlacklisted = Config.IsBlackListed(ipAddress) ||
                            Config.IsBlackListed(userName) ||
                            !Config.IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(userName) ||
                            (IPBanDelegate != null && IPBanDelegate.IsIPAddressBlacklisted(ipAddress));
                        int newCount = ipDB.IncrementFailedLoginCount(ipAddress, CurrentDateTime, failedLogin.Count);
                        IPBanLog.Info("Incremented count for ip {0} to {1}, user name: {2}", ipAddress, newCount, userName);

                        // if the ip address is black listed or the ip address has reached the maximum failed login attempts before ban, ban the ip address
                        if (configBlacklisted || newCount >= maxFailedLoginAttempts)
                        {
                            bool alreadyBanned = (ipDB.GetBanDate(ipAddress) != null);

                            // if the ip address is not already in the ban list, add it and mark it as needing to be banned
                            if (alreadyBanned)
                            {
                                IPBanLog.Info("IP {0}, {1}, {2} should already be banned, alreadyBanned == true.", ipAddress, userName, source);
                            }
                            else
                            {
                                if (IPBanDelegate != null)
                                {
                                    IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName).ConfigureAwait(false).GetAwaiter().GetResult();
                                }
                                AddBannedIPAddress(ipAddress, source, userName, bannedIpAddresses, now, configBlacklisted, newCount, string.Empty);
                            }
                        }
                        else if (newCount > maxFailedLoginAttempts)
                        {
                            IPBanLog.Info("IP {0}, {1}, {2} should already be banned.", ipAddress, newCount, source);
                        }
                        else
                        {
                            if (IPBanDelegate != null)
                            {
                                LoginFailedResult result = IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName).ConfigureAwait(false).GetAwaiter().GetResult();
                                if (result.HasFlag(LoginFailedResult.Blacklisted))
                                {
                                    AddBannedIPAddress(ipAddress, userName, source, bannedIpAddresses, now, configBlacklisted, newCount, "Delegate banned ip: " + result);
                                }
                            }
                            IPBanLog.Warn("Login attempt failed: {0}, {1}, {2}, {3}", ipAddress, userName, source, newCount);
                        }
                    }
                }
                catch (Exception ex)
                {
                    IPBanLog.Error(ex);
                }
            }

            // finish processing of pending banned ip addresses
            if (bannedIpAddresses.Count != 0)
            {
                ProcessBannedIPAddresses(bannedIpAddresses);
            }
        }

        protected virtual Task SubmitIPAddress(string ipAddress, string source, string userName)
        {
            if (System.Diagnostics.Debugger.IsAttached)
            {
                return Task.CompletedTask;
            }

            // submit url to ipban public database so that everyone can benefit from an aggregated list of banned ip addresses
            string timestamp = CurrentDateTime.ToString("o");
            string version = Assembly.GetAssembly(typeof(IPBanService)).GetName().Version.ToString();
            string url = $"/IPSubmitBanned?ip={ipAddress.UrlEncode()}&osname={OSName.UrlEncode()}&osversion={OSVersion.UrlEncode()}&source={source.UrlEncode()}&timestamp={timestamp.UrlEncode()}&userName={userName.UrlEncode()}&version={version.UrlEncode()}";
            string hash = Convert.ToBase64String(new SHA256Managed().ComputeHash(Encoding.UTF8.GetBytes(url + IPBanResources.IPBanKey1)));
            url += "&hash=" + hash.UrlEncode();
            url = "https://api.ipban.com" + url;

            try
            {
                return RequestMaker.MakeRequestAsync(new Uri(url));
            }
            catch
            {
                // don't care, this is not fatal
                return Task.CompletedTask;
            }
        }

        private void AddBannedIPAddress(string ipAddress, string source, string userName, List<KeyValuePair<string, string>> bannedIpAddresses,
            DateTime dateTime, bool configBlacklisted, int counter, string extraInfo)
        {
            bannedIpAddresses.Add(new KeyValuePair<string, string>(ipAddress, userName));
            ipDB.SetBanDate(ipAddress, dateTime);
            firewallNeedsBlockedIPAddressesUpdate = true;
            IPBanLog.Warn("Banning ip address: {0}, user name: {1}, config black listed: {2}, count: {3}, extra info: {4}",
                ipAddress, userName, configBlacklisted, counter, extraInfo);
            if (SubmitIPAddresses)
            {
                SubmitIPAddress(ipAddress, source, userName);
            }
        }

        private void ProcessBannedIPAddresses(IEnumerable<KeyValuePair<string, string>> bannedIPAddresses)
        {
            // kick off external process and delegate notification in another thread
            string programToRunConfigString = Config.ProcessToRunOnBan;
            RunTask(() =>
            {
                foreach (var bannedIp in bannedIPAddresses)
                {
                    // Run a process if one is in config
                    if (!string.IsNullOrWhiteSpace(programToRunConfigString))
                    {
                        try
                        {
                            string[] pieces = programToRunConfigString.Split('|');
                            if (pieces.Length == 2)
                            {
                                string program = pieces[0];
                                string arguments = pieces[1];
                                Process.Start(program, arguments.Replace("###IPADDRESS###", bannedIp.Key).Replace("###USERNAME###", bannedIp.Value));
                            }
                            else
                            {
                                throw new ArgumentException("Invalid config option for process to run on ban: " + programToRunConfigString);
                            }
                        }
                        catch (Exception ex)
                        {
                            IPBanLog.Error("Failed to execute process on ban", ex);
                        }
                    }
                    try
                    {
                        IPBanDelegate?.IPAddressBanned(bannedIp.Key, bannedIp.Value, true);
                    }
                    catch (Exception ex)
                    {
                        IPBanLog.Error("Error in delegate IPAddressBanned", ex);
                    }
                }
            });
        }

        private void UpdateBannedIPAddressesOnStart()
        {
            if (Config.ClearBannedIPAddressesOnRestart)
            {
                IPBanLog.Warn("Clearing all banned ip addresses on start because ClearBannedIPAddressesOnRestart is set");
                Firewall.BlockIPAddresses(new string[0]);
                ipDB.Truncate(true);
            }
            else
            {
                // make sure all banned ip addresses in the firewall are also in the database
                ipDB.SetBannedIPAddresses(Firewall.EnumerateBannedIPAddresses(), CurrentDateTime);

                // in case some banned ip are in the database but not in the firewall, force a firewall update
                firewallNeedsBlockedIPAddressesUpdate = true;

                // report on initial count
                int count = ipDB.GetIPAddressCount();
                IPBanLog.Warn("{0} total ip addresses in the {1} database", count, IPBanDB.FileName);
            }
        }

        private void LoadFirewall()
        {
            Firewall = IPBanFirewallUtility.CreateFirewall(Config.FirewallOSAndType, Config.FirewallRulePrefix);
        }

        private void CheckForExpiredIP()
        {
            List<string> ipAddressesToUnBan = new List<string>();
            List<string> ipAddressesToForget = new List<string>();
            DateTime now = CurrentDateTime;
            bool allowBanExpire = (Config.BanTime.TotalMilliseconds > 0.0);
            bool allowFailedLoginExpire = (Config.ExpireTime.TotalMilliseconds > 0.0);

            // loop the entire database to see if we need to unban or forget ip addresses
            foreach (IPBanDB.IPAddressEntry ipAddress in ipDB.EnumerateIPAddresses())
            {
                // never un-ban a blacklisted entry
                if (Config.IsBlackListed(ipAddress.IPAddress))
                {
                    continue;
                }
                // if ban duration has expired or ip is white listed, un-ban
                else if (ipAddress.BanDate != null)
                {
                    // if the ban has expired, or the ip address has become whitelisted, unban
                    bool banExpire = (allowBanExpire && (now - ipAddress.BanDate.Value) > Config.BanTime);
                    bool whitelisted = Config.IsIPAddressWhitelisted(ipAddress.IPAddress);
                    if (banExpire || whitelisted)
                    {
                        IPBanLog.Warn("Un-banning ip address {0}, ban expire: {1}, whitelisted: {2}", ipAddress.IPAddress, banExpire, whitelisted);
                        ipAddressesToUnBan.Add(ipAddress.IPAddress);

                        // firewall needs updating
                        firewallNeedsBlockedIPAddressesUpdate = true;
                    }
                }
                // if failed login has expired, remove the ip address
                else if (allowFailedLoginExpire)
                {
                    TimeSpan elapsed = (now - ipAddress.LastFailedLogin);
                    if (elapsed > Config.ExpireTime)
                    {
                        IPBanLog.Info("Forgetting ip address {0}, time expired", ipAddress.IPAddress);
                        ipAddressesToForget.Add(ipAddress.IPAddress);
                    }
                }
            }

            if (IPBanDelegate != null)
            {
                // notify delegate of ip addresses to unban
                foreach (string ip in ipAddressesToUnBan)
                {
                    IPBanDelegate.IPAddressBanned(ip, null, false);
                }
            }

            // now that we are done iterating the ip addresses, we can issue a delete
            ipDB.DeleteIPAddresses(ipAddressesToUnBan.Union(ipAddressesToForget));
        }

        private static bool IpAddressIsInRange(string ipAddress, string ipRange)
        {
            try
            {
                IPAddressRange range = IPAddressRange.Parse(ipRange);
                return range.Contains(IPAddress.Parse(ipAddress));

                /*
                string[] parts = ipRange.Split('/');
                int IP_addr = BitConverter.ToInt32(IPAddress.Parse(parts[0]).GetAddressBytes(), 0);
                int CIDR_addr = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);
                int CIDR_mask = IPAddress.HostToNetworkOrder(-1 << (32 - int.Parse(parts[1])));
                return ((IP_addr & CIDR_mask) == (CIDR_addr & CIDR_mask));
                */
            }
            catch
            {
                return false;
            }
        }

        private void UpdateDelegate()
        {
            if (IPBanDelegate == null)
            {
                return;
            }

            try
            {
                // we don't do the delegate update in a background thread because if it changes state, we need that done on the main loop thread
                if (IPBanDelegate.Update())
                {
                    DateTime now = CurrentDateTime;

                    // sync up the blacklist and whitelist from the delegate
                    foreach (string ip in IPBanDelegate.EnumerateBlackList())
                    {
                        firewallNeedsBlockedIPAddressesUpdate |= ipDB.SetBanDate(ip, now);
                    }

                    // get white list from delegate and remove any blacklisted ip that is now whitelisted
                    HashSet<string> allowIPAddresses = new HashSet<string>(IPBanDelegate.EnumerateWhiteList());

                    // add whitelist ip from config
                    if (!string.IsNullOrWhiteSpace(Config.WhiteList))
                    {
                        foreach (string ip in Config.WhiteList.Split(','))
                        {
                            string trimmedIP = ip.Trim();
                            if (IPAddressRange.TryParse(trimmedIP, out _))
                            {
                                allowIPAddresses.Add(trimmedIP);
                            }
                        }
                    }

                    foreach (string ip in allowIPAddresses)
                    {
                        // un-ban all whitelisted ip addresses
                        if (ipDB.DeleteIPAddress(ip))
                        {
                            IPBanLog.Info("Unbanning ip {0}, it is in the whitelist", ip);
                            firewallNeedsBlockedIPAddressesUpdate = true; // next loop will update the firewall
                        }
                        // check for subnet matches, unban any ip from the local subnet
                        else if (ip.Contains('/') && IPAddressRange.TryParse(ip, out IPAddressRange ipRange))
                        {
                            bool foundInRange = false;
                            foreach (string ipInRange in ipDB.DeleteIPAddresses(ipRange))
                            {
                                foundInRange = true;
                                IPBanLog.Info("Unbanning ip {0}, it is in the whitelist as a local subnet", ipInRange);
                            }
                            firewallNeedsBlockedIPAddressesUpdate |= foundInRange; // next loop will update the firewall
                        }
                    }

                    if (!ipAddressesToAllowInFirewall.SetEquals(allowIPAddresses))
                    {
                        // ensure that white list is explicitly allowed in the firewall
                        // in case of mass blocking of ip ranges, certain ip can still be allowed
                        ipAddressesToAllowInFirewall = allowIPAddresses;
                        ipAddressesToAllowInFirewallNeedsUpdate = true;
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error("Error in delegate Update", ex);
            }
        }

        private void GetUrl(UrlType urlType)
        {
            if ((urlType == UrlType.Start && gotStartUrl) || string.IsNullOrWhiteSpace(LocalIPAddressString) || string.IsNullOrWhiteSpace(FQDN))
            {
                return;
            }
            else if (urlType == UrlType.Stop)
            {
                gotStartUrl = false;
            }
            string url;
            switch (urlType)
            {
                case UrlType.Start: url = Config.GetUrlStart; break;
                case UrlType.Stop: url = Config.GetUrlStop; break;
                case UrlType.Update: url = Config.GetUrlUpdate; break;
                case UrlType.Config: url = Config.GetUrlConfig; break;
                default: return;
            }

            if (!string.IsNullOrWhiteSpace(url))
            {
                url = ReplaceUrl(url);
                RunTask(() =>
                {
                    try
                    {
                        byte[] bytes = RequestMaker.MakeRequestAsync(new Uri(url)).Sync();
                        if (urlType == UrlType.Start)
                        {
                            gotStartUrl = true;
                        }
                        else if (urlType == UrlType.Update)
                        {
                            // if the update url sends bytes, we assume a software update, and run the result as an .exe
                            if (bytes.Length != 0)
                            {
                                string tempFile = Path.Combine(Path.GetTempPath(), "IPBanServiceUpdate.exe");
                                File.WriteAllBytes(tempFile, bytes);

                                // however you are doing the update, you must allow -c and -d parameters
                                // pass -c to tell the update executable to delete itself when done
                                // pass -d for a directory which tells the .exe where this service lives
                                string args = "-c \"-d=" + AppDomain.CurrentDomain.BaseDirectory + "\"";
                                Process.Start(tempFile, args);
                            }
                        }
                        else if (urlType == UrlType.Config && bytes.Length != 0)
                        {
                            UpdateConfig(Encoding.UTF8.GetString(bytes));
                        }
                    }
                    catch (Exception ex)
                    {
                        IPBanLog.Error(ex, "Error getting url of type {0} at {1}", urlType, url);
                    }
                });
            }
        }

        private void UpdateUpdaters()
        {
            List<IUpdater> updatersTemp;

            // lock only long enough to copy the updaters
            lock (updaters)
            {
                updatersTemp = new List<IUpdater>(updaters);
            }

            // loop through temp list so we don't lock for very long
            foreach (IUpdater updater in updatersTemp)
            {
                updater.Update();
            }
        }

        private void UpdateFirewall()
        {
            if (firewallNeedsBlockedIPAddressesUpdate)
            {
                firewallNeedsBlockedIPAddressesUpdate = false;
                if (ipDB.GetBannedIPAddressCount() == 0)
                {
                    IPBanLog.Warn("Clearing all block firewall rules because {0} is empty", IPBanDB.FileName);
                }
                Firewall.BlockIPAddresses(ipDB.EnumerateBannedIPAddresses().Select(i => i.IPAddress));
            }

            // update firewall if needed
            if (ipAddressesToAllowInFirewallNeedsUpdate)
            {
                ipAddressesToAllowInFirewallNeedsUpdate = false;

                // if the config specifies that we should create a whitelist firewall rule, do so
                if (Config.CreateWhitelistFirewallRule)
                {
                    // quickly copy out data in a lock, always lock ipAddressesAndBanDate
                    string[] ipAddresses = ipAddressesToAllowInFirewall?.ToArray();
                    ipAddressesToAllowInFirewall = null;

                    if (ipAddresses != null)
                    {
                        // re-create rules for all allowed ip addresses
                        Firewall.AllowIPAddresses(ipAddresses);
                    }
                }
            }
        }

        private void CycleTimerElapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (IsRunning)
            {
                try
                {
                    cycleTimer.Stop();
                    RunCycle();
                }
                catch (Exception ex)
                {
                    // should not get here, but if we do log it and sleep a bit in case of repeating error
                    IPBanLog.Error(ex);
                    Thread.Sleep(5000);
                }
                finally
                {
                    try
                    {
                        cycleTimer.Start();
                    }
                    catch
                    {
                    }
                }
                IPBanLog.Trace("CycleTimerElapsed");
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        protected IPBanService()
        {
            OSName = IPBanOS.Name + (string.IsNullOrWhiteSpace(IPBanOS.FriendlyName) ? string.Empty : " (" + IPBanOS.FriendlyName + ")");
            OSVersion = IPBanOS.Version;
        }

        /// <summary>
        /// Create an IPBanService by searching all types in all assemblies
        /// </summary>
        /// <param name="testing">True if testing, false otherwise. Testing mode disables certain features that are not needed in test mode.
        /// In test mode manual cycle is true and multi-threaded is false.</param>
        /// <returns>IPBanService (if not found an exception is thrown)</returns>
        public static IPBanService CreateService(bool testing = false)
        {
            // if any derived class of IPBanService, use that
            var q =
                from a in AppDomain.CurrentDomain.GetAssemblies().SelectMany(a => a.GetTypes())
                where a.IsSubclassOf(typeof(IPBanService))
                select a;
            Type instanceType = (q.FirstOrDefault() ?? typeof(IPBanService));
            IPBanService service = (IPBanService)Activator.CreateInstance(instanceType, BindingFlags.NonPublic | BindingFlags.Instance, null, null, null);
            if (testing)
            {
                service.MultiThreaded = false;
                service.ManualCycle = true;
                service.SubmitIPAddresses = false;
                service.ipDB.Truncate(true);
            }
            return service;
        }

        /// <summary>
        /// Manually run one cycle. This is called automatically, unless ManualCycle is true.
        /// </summary>
        public void RunCycle()
        {
            ReadAppSettings();
            SetNetworkInfo();
            UpdateDelegate();
            CheckForExpiredIP();
            ProcessPendingFailedLogins();
            UpdateUpdaters();
            UpdateFirewall();
        }

        /// <summary>
        /// Manually process all pending ip addresses. This is usually called automatically.
        /// </summary>
        public void ProcessPendingFailedLogins()
        {
            // make a quick copy of pending ip addresses so we don't lock it for very long
            List<FailedLogin> ipAddresses;
            lock (pendingFailedLogins)
            {
                if (pendingFailedLogins.Count == 0)
                {
                    return;
                }
                ipAddresses = new List<FailedLogin>(pendingFailedLogins);
                pendingFailedLogins.Clear();
            }
            ProcessPendingFailedLogins(ipAddresses);
        }

        /// <summary>
        /// Add an ip address to be checked for banning later
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <param name="source">Source</param>
        /// <param name="userName">User Name</param>
        public void AddFailedLogin(string ipAddress, string source, string userName, int count)
        {
            if (ipAddress == "::1" || ipAddress == "127.0.0.1")
            {
                return;
            }

            source = (source ?? "?");
            userName = (userName ?? string.Empty);
            lock (pendingFailedLogins)
            {
                FailedLogin existing = pendingFailedLogins.FirstOrDefault(p => p.IPAddress == ipAddress && (p.UserName == null || p.UserName == userName));
                if (existing == null)
                {
                    existing = new FailedLogin
                    {
                        IPAddress = ipAddress,
                        Source = source,
                        UserName = userName,
                        DateTime = CurrentDateTime,
                        Count = count
                    };
                    pendingFailedLogins.Add(existing);
                }
                else
                {
                    existing.UserName = (existing.UserName ?? userName);

                    // if more than n seconds has passed, increment the counter
                    // we don't want to count multiple event logs that all map to the same ip address from one failed
                    // attempt to count multiple times
                    if ((CurrentDateTime - existing.DateTime) >= Config.MinimumTimeBetweenFailedLoginAttempts)
                    {
                        existing.DateTime = CurrentDateTime;
                        existing.Count += count;
                    }
                    else
                    {
                        IPBanLog.Info("Ignoring failed login from {0}, min time between failed logins has not elapsed", existing.IPAddress);
                    }
                }
            }
        }

        /// <summary>
        /// Get an ip address and user name out of text using regex
        /// </summary>
        /// <param name="dns">Dns lookup to resolve ip addresses</param>
        /// <param name="regex">Regex</param>
        /// <param name="text">Text</param>
        /// <param name="ipAddress">Found ip address or null if none</param>
        /// <param name="userName">Found user name or null if none</param>
        /// <returns>True if a regex match was found, false otherwise</returns>
        public static bool GetIPAddressAndUserNameFromRegex(IDnsLookup dns, Regex regex, string text, ref string ipAddress, ref string userName)
        {
            bool foundMatch = false;

            foreach (Match m in regex.Matches(text))
            {
                if (!m.Success)
                {
                    continue;
                }

                // check for a user name
                Group userNameGroup = m.Groups["username"];
                if (userNameGroup != null && userNameGroup.Success)
                {
                    userName = (userName ?? userNameGroup.Value.Trim('\'', '\"', '(', ')', '[', ']', '{', '}', ' ', '\r', '\n'));
                }

                // check if the regex had an ipadddress group
                Group ipAddressGroup = m.Groups["ipaddress"];
                if (ipAddressGroup != null && ipAddressGroup.Success && !string.IsNullOrWhiteSpace(ipAddressGroup.Value))
                {
                    string tempIPAddress = ipAddressGroup.Value.Trim();

                    // in case of IP:PORT format, try a second time, stripping off the :PORT, saves having to do this in all
                    //  the different ip regex.
                    int lastColon = tempIPAddress.LastIndexOf(':');
                    if (IPAddress.TryParse(tempIPAddress, out IPAddress tmp) ||
                        (lastColon >= 0 && IPAddress.TryParse(tempIPAddress.Substring(0, lastColon), out tmp)))
                    {
                        ipAddress = tmp.ToString();
                        foundMatch = true;
                        break;
                    }

                    if (tempIPAddress != Environment.MachineName && tempIPAddress != "-")
                    {
                        // Check Host by name
                        IPBanLog.Info("Parsing as IP failed, checking dns '{0}'", tempIPAddress);
                        try
                        {
                            IPHostEntry entry = dns.GetHostEntryAsync(tempIPAddress).Sync();
                            if (entry != null && entry.AddressList != null && entry.AddressList.Length > 0)
                            {
                                ipAddress = entry.AddressList.FirstOrDefault().ToString();
                                IPBanLog.Info("Dns result '{0}' = '{1}'", tempIPAddress, ipAddress);
                                foundMatch = true;
                                break;
                            }
                        }
                        catch
                        {
                            IPBanLog.Info("Parsing as dns failed '{0}'", tempIPAddress);
                        }
                    }
                }
                else
                {
                    // found a match but no ip address, that is OK.
                    foundMatch = true;
                }
            }

            if (!foundMatch)
            {
                ipAddress = null;
            }

            return foundMatch;
        }

        /// <summary>
        /// Write a new config file
        /// </summary>
        /// <param name="xml">Xml of the new config file</param>
        public void UpdateConfig(string xml)
        {
            try
            {
                // Ensure valid xml before writing the file
                XmlDocument doc = new XmlDocument();
                using (XmlReader xmlReader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { CheckCharacters = false }))
                {
                    doc.Load(xmlReader);
                }
                lock (configLock)
                {
                    string text = File.ReadAllText(ConfigFilePath);

                    // if the file changed, update it
                    if (text != xml)
                    {
                        File.WriteAllText(ConfigFilePath, xml);
                    }
                }
            }
            catch
            {
            }
        }

        /// <summary>
        /// Stop the service, dispose of all resources
        /// </summary>
        public void Dispose()
        {
            if (!IsRunning)
            {
                return;
            }

            IsRunning = false;
            GetUrl(UrlType.Stop);
            try
            {
                cycleTimer?.Dispose();
                IPBanDelegate?.Stop();
                IPBanDelegate?.Dispose();
            }
            catch
            {
            }
            IPBanDelegate = null;
            try
            {
                lock (updaters)
                {
                    foreach (IUpdater updater in updaters.ToArray())
                    {
                        updater.Dispose();
                    }
                    updaters.Clear();
                }
            }
            catch
            {
            }
            try
            {
                foreach (IPBanLogFileScanner file in logFilesToParse)
                {
                    file.Dispose();
                }
            }
            catch
            {
            }
            logFilesToParse.Clear();
            IPBanLog.Warn("Stopped IPBan service");
        }

        /// <summary>
        /// Initialize and start the service
        /// </summary>
        public void Start()
        {
            if (IsRunning)
            {
                return;
            }

            IsRunning = true;
            ReadAppSettings();
            LoadFirewall();
            UpdateBannedIPAddressesOnStart();
            LogInitialConfig();
            IPBanDelegate?.Start(this);
            if (!ManualCycle)
            {
                RunCycle(); // run one cycle right away
                cycleTimer = new System.Timers.Timer(Config.CycleTime.TotalMilliseconds);
                cycleTimer.Elapsed += CycleTimerElapsed;
                cycleTimer.Start();
            }
            IPBanLog.Warn("IPBan service started and initialized. Operating System: {0}", IPBanOS.OSString());
            IPBanLog.WriteLogLevels();
        }

        /// <summary>
        /// Calls Dispose
        /// </summary>
        public void Stop()
        {
            Dispose();
        }

        /// <summary>
        /// Replace place-holders in url with values from this service
        /// </summary>
        /// <param name="url">Url to replace</param>
        /// <returns>Replaced url</returns>
        public string ReplaceUrl(string url)
        {
            Assembly a = IPBanService.GetIPBanAssembly();
            return url.Replace("###IPADDRESS###", LocalIPAddressString.UrlEncode())
                .Replace("###REMOTE_IPADDRESS###", RemoteIPAddressString.UrlEncode())
                .Replace("###MACHINENAME###", FQDN.UrlEncode())
                .Replace("###VERSION###", a.GetName().Version.ToString().UrlEncode())
                .Replace("###GUID###", MachineGuid.UrlEncode())
                .Replace("###OSNAME###", OSName.UrlEncode())
                .Replace("###OSVERSION###", OSVersion.UrlEncode());
        }

        /// <summary>
        /// Get a list of ip address and failed login attempts
        /// </summary>
        public IEnumerable<IPBanDB.IPAddressEntry> FailedLoginAttempts
        {
            get { return ipDB.EnumerateIPAddresses(); }
        }

        /// <summary>
        /// Get the IPBan assembly
        /// </summary>
        /// <returns>IPBan assembly</returns>
        public static Assembly GetIPBanAssembly()
        {
            return typeof(IPBanService).Assembly;
        }

        /// <summary>
        /// Add an updater for each cycle
        /// </summary>
        /// <param name="updater">Updater</param>
        /// <returns>True if added, false if null or already in the list</returns>
        public bool AddUpdater(IUpdater updater)
        {
            if (updater != null)
            {
                lock (updaters)
                {
                    return updaters.Add(updater);
                }
            }
            return false;
        }

        /// <summary>
        /// Attempt to get an updater of a specific type
        /// </summary>
        /// <typeparam name="T">Type</typeparam>
        /// <param name="result">Updater or default(T) if not found</param>
        /// <returns>True if found, false if not</returns>
        public bool TryGetUpdater<T>(out T result)
        {
            lock (updaters)
            {
                foreach (IUpdater updater in updaters)
                {
                    if (updater is T result2)
                    {
                        result = result2;
                        return true;
                    }
                }
            }
            result = default;
            return false;
        }

        /// <summary>
        /// Remove an updater
        /// </summary>
        /// <param name="result">Updater</param>
        /// <returns>True if removed, false otherwise</returns>
        public bool RemoveUpdater(IUpdater updater)
        {
            lock (updaters)
            {
                return updaters.Remove(updater);
            }
        }

        /// <summary>
        /// Config file path
        /// </summary>
        public string ConfigFilePath { get; set; }

        /// <summary>
        /// Http request maker, defaults to DefaultHttpRequestMaker
        /// </summary>
        public IHttpRequestMaker RequestMaker { get; set; } = DefaultHttpRequestMaker.Instance;

        /// <summary>
        /// The firewall implementation - this will auto-detect if not set
        /// </summary>
        public IIPBanFirewall Firewall { get; set; }

        /// <summary>
        /// The dns implementation - defaults to DefaultDnsLookup
        /// </summary>
        public IDnsLookup DnsLookup { get; set; } = DefaultDnsLookup.Instance;

        /// <summary>
        /// External ip address implementation - defaults to ExternalIPAddressLookupDefault.Instance
        /// </summary>
        public ILocalMachineExternalIPAddressLookup ExternalIPAddressLookup { get; set; } = LocalMachineExternalIPAddressLookupDefault.Instance;

        /// <summary>
        /// Configuration
        /// </summary>
        public IPBanConfig Config { get; private set; }

        /// <summary>
        /// Local ip address
        /// </summary>
        public string LocalIPAddressString { get; private set; }

        /// <summary>
        /// Remote ip address
        /// </summary>
        public string RemoteIPAddressString { get; private set; }

        /// <summary>
        /// Fully qualified domain name
        /// </summary>
        public string FQDN { get; private set; }

        /// <summary>
        /// Machine guid, null/empty for none
        /// </summary>
        public string MachineGuid { get; set; }

        /// <summary>
        /// External delegate to allow external config, whitelist, blacklist, etc.
        /// </summary>
        public IIPBanDelegate IPBanDelegate { get; set; }

        /// <summary>
        /// Whether delegate callbacks and other tasks are multithreaded. Default is true. Set to false if unit or integration testing.
        /// </summary>
        public bool MultiThreaded { get; private set; } = true;

        /// <summary>
        /// True if the cycle is manual, in which case RunCycle must be called periodically, otherwise if false RunCycle is called automatically.
        /// </summary>
        public bool ManualCycle { get; private set; }

        /// <summary>
        /// The operating system name. If null, it is auto-detected.
        /// </summary>
        public string OSName { get; private set; }

        /// <summary>
        /// The operating system version. If null, it is auto-detected.
        /// </summary>
        public string OSVersion { get; private set; }
        
        private DateTime? currentDateTime;
        /// <summary>
        /// Allows changing the current date time to facilitate testing of behavior over elapsed times
        /// </summary>
        public DateTime CurrentDateTime
        {
            get { return currentDateTime ?? DateTime.UtcNow; }
            set { currentDateTime = (value == default ? null : (DateTime?)value); }
        }

        /// <summary>
        /// Whether the service is currently running
        /// </summary>
        public bool IsRunning { get; set; }

        /// <summary>
        /// Whether to submit ip addresses for global ban list
        /// </summary>
        public bool SubmitIPAddresses { get; set; } = true;
    }

    /// <summary>
    /// Allows updating periodically
    /// </summary>
    public interface IUpdater : IDisposable
    {
        /// <summary>
        /// Update
        /// </summary>
        void Update();
    }
}
