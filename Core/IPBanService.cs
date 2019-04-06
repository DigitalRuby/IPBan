/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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

namespace DigitalRuby.IPBan
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

        private class BannedIPAddress
        {
            public string IPAddress { get; set; }
            public string Source { get; set; }
            public string UserName { get; set; }
        }

        private class FailedLogin : BannedIPAddress
        {
            public DateTime DateTime { get; set; }
            public int Count { get; set; }
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
            foreach (IPBanLogFileToParse newFile in newConfig.LogFilesToParse)
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
                            IPBanLogFileScanner scanner = new IPBanIPAddressLogFileScanner(this, DnsLookup,
                                newFile.Source, pathAndMask, newFile.Recursive, newFile.FailedLoginRegex, newFile.SuccessfulLoginRegex, newFile.MaxFileSize, newFile.PingInterval);
                            logFilesToParse.Add(scanner);
                        }
                        else
                        {
                            IPBanLog.Debug("Ignoring log file path {0}, regex: {1}", pathAndMask, newFile.PlatformRegex);
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

        private async Task SetNetworkInfo()
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
                    IPAddress[] ips = await DnsLookup.GetHostAddressesAsync(Dns.GetHostName());
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
                    IPAddress ipAddress = await ExternalIPAddressLookup.LookupExternalIPAddressAsync(RequestMaker, Config.ExternalIPAddressUrl);
                    RemoteIPAddressString = ipAddress.ToString();
                    IPBanLog.Info("Remote ip address: {0}", RemoteIPAddressString);
                }
                catch
                {

                }
            }

            // hit start url if first time, if not first time will be ignored
            await GetUrl(UrlType.Start);

            // send update
            await GetUrl(UrlType.Update);

            // request new config file
            await GetUrl(UrlType.Config);
        }

        private void LogInitialConfig()
        {
            IPBanLog.Info("Whitelist: {0}, Whitelist Regex: {1}", Config.WhiteList, Config.WhiteListRegex);
            IPBanLog.Info("Blacklist: {0}, Blacklist Regex: {1}", Config.BlackList, Config.BlackListRegex);
        }

        private async Task ProcessPendingFailedLogins(IEnumerable<FailedLogin> ipAddresses)
        {
            List<BannedIPAddress> bannedIpAddresses = new List<BannedIPAddress>();
            foreach (FailedLogin failedLogin in ipAddresses)
            {
                try
                {
                    string ipAddress = failedLogin.IPAddress;
                    string userName = failedLogin.UserName;
                    string source = failedLogin.Source;
                    if (Config.IsWhitelisted(ipAddress) ||
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
                        int newCount = ipDB.IncrementFailedLoginCount(ipAddress, UtcNow, failedLogin.Count);
                        IPBanLog.Warn("Login attempt failed: {0}, {1}, {2}, {3}", ipAddress, userName, source, newCount);

                        // if the ip address is black listed or the ip address has reached the maximum failed login attempts before ban, ban the ip address
                        if (configBlacklisted || newCount >= maxFailedLoginAttempts)
                        {
                            bool alreadyBanned = (ipDB.GetBanDate(ipAddress) != null);
                            if (alreadyBanned)
                            {
                                IPBanLog.Info("IP {0}, {1}, {2} ban pending.", ipAddress, userName, source);
                            }
                            else if (IPBanDelegate == null || (await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName) != LoginFailedResult.Whitelisted))
                            {
                                await AddBannedIPAddress(ipAddress, source, userName, bannedIpAddresses, now, configBlacklisted, newCount, string.Empty);
                            }
                        }
                        else if (newCount > maxFailedLoginAttempts)
                        {
                            IPBanLog.Info("IP {0}, {1}, {2} ban pending.", ipAddress, newCount, source);
                        }
                        else
                        {
                            // failed login attempt
                            if (IPBanDelegate != null)
                            {
                                LoginFailedResult result = await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName);
                                if (result.HasFlag(LoginFailedResult.Blacklisted))
                                {
                                    await AddBannedIPAddress(ipAddress, userName, source, bannedIpAddresses, now, configBlacklisted, newCount, "Delegate banned ip: " + result);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    IPBanLog.Error(ex);
                }
            }

            ExecuteExternalProcessForBannedIPAddresses(bannedIpAddresses);
        }

        private async Task AddBannedIPAddress(string ipAddress, string source, string userName, List<BannedIPAddress> bannedIpAddresses,
            DateTime dateTime, bool configBlacklisted, int counter, string extraInfo)
        {
            bannedIpAddresses.Add(new BannedIPAddress { IPAddress = ipAddress, Source = source, UserName = userName });
            ipDB.SetBanDate(ipAddress, dateTime);
            firewallNeedsBlockedIPAddressesUpdate = true;
            IPBanLog.Warn("Banning ip address: {0}, user name: {1}, config black listed: {2}, count: {3}, extra info: {4}",
                ipAddress, userName, configBlacklisted, counter, extraInfo);

            if (BannedIPAddressHandler != null && System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj) && !ipAddressObj.IsInternal())
            {
                await BannedIPAddressHandler.HandleBannedIPAddress(ipAddress, source, userName, OSName, OSVersion, AssemblyVersion, RequestMaker);
            }
            if (IPBanDelegate != null)
            {
                await IPBanDelegate.IPAddressBanned(ipAddress, source, userName, true);
            }
        }

        private void ExecuteExternalProcessForBannedIPAddresses(IReadOnlyCollection<BannedIPAddress> bannedIPAddresses)
        {
            if (bannedIPAddresses.Count == 0)
            {
                return;
            }

            // kick off external process and delegate notification in another thread
            string programToRunConfigString = (Config.ProcessToRunOnBan ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(programToRunConfigString))
            {
                return;
            }

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
                                Process.Start(program, arguments.Replace("###IPADDRESS###", bannedIp.IPAddress)
                                    .Replace("###SOURCE###", bannedIp.Source)
                                    .Replace("###USERNAME###", bannedIp.UserName));
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
                }
            });
        }

        private void UpdateBannedIPAddressesOnStart()
        {
            if (Config.ClearBannedIPAddressesOnRestart)
            {
                IPBanLog.Warn("Clearing all banned ip addresses on start because ClearBannedIPAddressesOnRestart is set");
                Firewall.BlockIPAddresses(new string[0]).Sync();
                ipDB.Truncate(true);
            }
            else
            {
                // make sure all banned ip addresses in the firewall are also in the database
                ipDB.SetBannedIPAddresses(Firewall.EnumerateBannedIPAddresses(), UtcNow);

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

        private async Task CheckForExpiredIP()
        {
            List<string> ipAddressesToUnBan = new List<string>();
            List<string> ipAddressesToForget = new List<string>();
            DateTime now = UtcNow;
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
                    bool whitelisted = Config.IsWhitelisted(ipAddress.IPAddress);
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
                    await IPBanDelegate.IPAddressBanned(ip, null, null, false);
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
                    DateTime now = UtcNow;

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

        private async Task GetUrl(UrlType urlType)
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
                try
                {
                    byte[] bytes = await RequestMaker.MakeRequestAsync(new Uri(url));
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
                if (MultiThreaded)
                {
                    TaskQueue.Add(() => Firewall.BlockIPAddresses(ipDB.EnumerateBannedIPAddresses().Select(i => i.IPAddress), TaskQueue.GetToken()));
                }
                else
                {
                    Firewall.BlockIPAddresses(ipDB.EnumerateBannedIPAddresses().Select(i => i.IPAddress)).Sync();
                }
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
                        if (MultiThreaded)
                        {
                            TaskQueue.Add(() => Firewall.AllowIPAddresses(ipAddresses, TaskQueue.GetToken()));
                        }
                        else
                        {
                            // re-create rules for all allowed ip addresses
                            Firewall.AllowIPAddresses(ipAddresses).Sync();
                        }
                    }
                }
            }
        }

        private async Task CycleTimerElapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (IsRunning)
            {
                try
                {
                    cycleTimer.Stop();
                    await RunCycle();
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
        /// <returns>IPBanService (if not found an exception is thrown)</returns>
        public static T CreateService<T>() where T : IPBanService
        {
            Type typeOfT = typeof(T);

            // if any derived class of IPBanService, use that
            var q =
                from type in AppDomain.CurrentDomain.GetAssemblies().SelectMany(a => a.GetTypes())
                where typeOfT.IsAssignableFrom(type)
                select type;
            Type instanceType = (q.FirstOrDefault() ?? typeof(IPBanService));
            return Activator.CreateInstance(instanceType, BindingFlags.NonPublic | BindingFlags.Instance, null, null, null) as T;
        }

        /// <summary>
        /// Manually run one cycle. This is called automatically, unless ManualCycle is true.
        /// </summary>
        public async Task RunCycle()
        {
            ReadAppSettings();
            await SetNetworkInfo();
            UpdateDelegate();
            UpdateUpdaters();
            await ProcessPendingFailedLogins();
        }

        /// <summary>
        /// Manually process all pending ip addresses. This is usually called automatically.
        /// </summary>
        public async Task ProcessPendingFailedLogins()
        {
            await CheckForExpiredIP();

            // make a quick copy of pending ip addresses so we don't lock it for very long
            List<FailedLogin> ipAddresses = null;
            lock (pendingFailedLogins)
            {
                if (pendingFailedLogins.Count != 0)
                {
                    ipAddresses = new List<FailedLogin>(pendingFailedLogins);
                    pendingFailedLogins.Clear();
                }
            }
            if (ipAddresses != null)
            {
                await ProcessPendingFailedLogins(ipAddresses);
            }
            UpdateFirewall();
        }

        /// <summary>
        /// Add an ip address to be checked for banning later
        /// </summary>
        /// <param name="info">IP address log info</param>
        /// <returns>Task</returns>
        public Task HandleIPAddressEvent(IPAddressEvent info)
        {
            if (IPBanFirewallUtility.TryGetFirewallIPAddress(info.IPAddress, out string normalizedIPAddress))
            {
                info.Source = (info.Source ?? "?");
                info.UserName = (info.UserName ?? string.Empty);
                if (info.Flag.HasFlag(IPAddressEventFlag.FailedLogin))
                {
                    lock (pendingFailedLogins)
                    {
                        FailedLogin existing = pendingFailedLogins.FirstOrDefault(p => p.IPAddress == normalizedIPAddress && (p.UserName == null || p.UserName == info.UserName));
                        if (existing == null)
                        {
                            existing = new FailedLogin
                            {
                                IPAddress = normalizedIPAddress,
                                Source = info.Source,
                                UserName = info.UserName,
                                DateTime = UtcNow,
                                Count = info.Count
                            };
                            pendingFailedLogins.Add(existing);
                        }
                        else
                        {
                            existing.UserName = (existing.UserName ?? info.UserName);

                            // if more than n seconds has passed, increment the counter
                            // we don't want to count multiple event logs that all map to the same ip address from one failed
                            // attempt to count multiple times
                            if ((UtcNow - existing.DateTime) >= Config.MinimumTimeBetweenFailedLoginAttempts)
                            {
                                existing.DateTime = UtcNow;
                                existing.Count += info.Count;
                            }
                            else
                            {
                                IPBanLog.Info("Ignoring failed login from {0}, min time between failed logins has not elapsed", existing.IPAddress);
                            }
                        }
                    }
                }
                else if (IPBanDelegate != null)
                {
                    if (MultiThreaded)
                    {
                        // pass the success login on
                        return IPBanDelegate.LoginAttemptSucceeded(info.IPAddress, info.Source, info.UserName);
                    }

                    // single threaded
                    IPBanDelegate.LoginAttemptSucceeded(info.IPAddress, info.Source, info.UserName).Sync();
                }
            }
            return Task.CompletedTask;
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
        public static IPAddressEvent GetIPAddressInfoFromRegex(IDnsLookup dns, Regex regex, string text)
        {
            bool foundMatch = false;
            string userName = null;
            string ipAddress = null;
            string source = null;
            int repeatCount = 1;

            Match repeater = Regex.Match(text, "message repeated (?<count>[0-9]+) times", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (repeater.Success)
            {
                repeatCount = int.Parse(repeater.Groups["count"].Value, CultureInfo.InvariantCulture);
            }

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
                Group sourceGroup = m.Groups["source"];
                if (sourceGroup != null && sourceGroup.Success)
                {
                    source = (source ?? sourceGroup.Value.Trim('\'', '\"', '(', ')', '[', ']', '{', '}', ' ', '\r', '\n'));
                }

                // check if the regex had an ipadddress group
                Group ipAddressGroup = m.Groups["ipaddress"];
                if (ipAddressGroup == null)
                {
                    ipAddressGroup = m.Groups["ipaddress_exact"];
                }
                if (ipAddressGroup != null && ipAddressGroup.Success && !string.IsNullOrWhiteSpace(ipAddressGroup.Value))
                {
                    string tempIPAddress = ipAddressGroup.Value.Trim();

                    // in case of IP:PORT format, try a second time, stripping off the :PORT, saves having to do this in all
                    //  the different ip regex.
                    int lastColon = tempIPAddress.LastIndexOf(':');
                    bool isValidIPAddress = IPAddress.TryParse(tempIPAddress, out IPAddress tmp);
                    if (isValidIPAddress || (lastColon >= 0 && IPAddress.TryParse(tempIPAddress.Substring(0, lastColon), out tmp)))
                    {
                        ipAddress = tmp.ToString();
                        foundMatch = true;
                        break;
                    }

                    // if we are parsing anything as ip address (including dns names)
                    if (ipAddressGroup.Name == "ipaddress" && tempIPAddress != Environment.MachineName && tempIPAddress != "-")
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

            return new IPAddressEvent(foundMatch, ipAddress, userName, source, repeatCount, IPAddressEventFlag.FailedLogin);
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

            TaskQueue.Dispose();
            IsRunning = false;
            GetUrl(UrlType.Stop).Sync();
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
            ipDB.Dispose();
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

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // attach Windows event viewer to the service
                EventViewer = new IPBanWindowsEventViewer(this);
            }

            IsRunning = true;
            AddUpdater(new IPBanUnblockIPAddressesUpdater(this, Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "unban.txt")));
            AssemblyVersion = IPBanService.GetIPBanAssembly().GetName().Version.ToString();
            ReadAppSettings();
            LoadFirewall();
            UpdateBannedIPAddressesOnStart();
            LogInitialConfig();
            IPBanDelegate?.Start(this);
            if (!ManualCycle)
            {
                RunCycle().Sync(); // run one cycle right away
                cycleTimer = new System.Timers.Timer(Config.CycleTime.TotalMilliseconds);
                cycleTimer.Elapsed += async (sender, e) => await CycleTimerElapsed(sender, e);
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
        /// Unban ip addresses
        /// </summary>
        /// <param name="ipAddresses">IP addresses to unban</param>
        public void UnblockIPAddresses(IEnumerable<string> ipAddresses)
        {
            // remove ip from firewall
            Firewall.UnblockIPAddresses(ipAddresses);

            // remove ip from database
            DB.DeleteIPAddresses(ipAddresses);

            // ip addresses are now unbanned
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
                .Replace("###REMOTEIPADDRESS###", RemoteIPAddressString.UrlEncode())
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
        /// Create a test IPBanService
        /// </summary>
        /// <param name="directory">Root directory</param>
        /// <param name="configFileName">Config file name</param>
        /// <param name="configFileModifier">Change config file (param are file text, returns new file text)</param>
        /// <returns>Service</returns>
        public static T CreateAndStartIPBanTestService<T>(string directory = null, string configFileName = null,
            Func<string, string> configFileModifier = null) where T : IPBanService
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                Assembly a = IPBanService.GetIPBanAssembly();
                directory = Path.GetDirectoryName(a.Location);
            }
            if (string.IsNullOrWhiteSpace(configFileName))
            {
                Assembly a = IPBanService.GetIPBanAssembly();
                configFileName = IPBanService.ConfigFileName;
            }
            string configFilePath = Path.Combine(directory, configFileName);
            string configFileText = File.ReadAllText(configFilePath);
            if (configFileModifier != null)
            {
                configFileText = configFileModifier(configFileText);
                File.WriteAllText(configFilePath, configFileText);
            }
            T service = IPBanService.CreateService<T>() as T;
            service.ExternalIPAddressLookup = LocalMachineExternalIPAddressLookupTest.Instance;
            service.ConfigFilePath = configFilePath;
            service.MultiThreaded = false;
            service.ManualCycle = true;
            service.BannedIPAddressHandler = null; // no external ip handling
            service.Start();
            service.DB.Truncate(true);
            service.Firewall.BlockIPAddresses(new string[0]).Sync();
            return service;
        }

        /// <summary>
        /// Config file name
        /// </summary>
        public const string ConfigFileName = "DigitalRuby.IPBan.dll.config";

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
        /// Extra handler for banned ip addresses (optional)
        /// </summary>
        public IBannedIPAddressHandler BannedIPAddressHandler { get; set; } = new DefaultBannedIPAddressHandler();

        /// <summary>
        /// Serial task queue
        /// </summary>
        public SerialTaskQueue TaskQueue { get; } = new SerialTaskQueue();

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
        public bool MultiThreaded { get; set; } = true;

        /// <summary>
        /// True if the cycle is manual, in which case RunCycle must be called periodically, otherwise if false RunCycle is called automatically.
        /// </summary>
        public bool ManualCycle { get; set; }

        /// <summary>
        /// The operating system name. If null, it is auto-detected.
        /// </summary>
        public string OSName { get; private set; }

        /// <summary>
        /// The operating system version. If null, it is auto-detected.
        /// </summary>
        public string OSVersion { get; private set; }

        /// <summary>
        /// Assembly version
        /// </summary>
        public string AssemblyVersion { get; private set; }

        /// <summary>
        /// Event viewer (null if not on Windows)
        /// </summary>
        public IPBanWindowsEventViewer EventViewer { get; private set; }

        private static DateTime? utcNow;
        /// <summary>
        /// Allows changing the current date time to facilitate testing of behavior over elapsed times. Set to default(DateTime) to revert to DateTime.UtcNow.
        /// </summary>
        public static DateTime UtcNow
        {
            get { return utcNow ?? DateTime.UtcNow; }
            set { utcNow = (value == default ? null : (DateTime?)value); }
        }

        /// <summary>
        /// Whether the service is currently running
        /// </summary>
        public bool IsRunning { get; set; }

        /// <summary>
        /// IPBan database
        /// </summary>
        public IPBanDB DB { get { return ipDB; } }

        /// <summary>
        /// File name to write ip addresses to (one per line) to unblock the ip addresses in the file
        /// </summary>
        public string UnblockIPAddressesFileName { get; } = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "unban.txt");
    }

    /// <summary>
    /// Information about an ip address from a log entry
    /// </summary>
    public class IPAddressEvent
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public IPAddressEvent() { } 

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="foundMatch">Whether a match was found</param>
        /// <param name="ipAddress">IP address</param>
        /// <param name="userName">User name</param>
        /// <param name="source">Source</param>
        /// <param name="count">How many messages were aggregated, 1 for no aggregation</param>
        /// <param name="flag">Event flag</param>
        public IPAddressEvent(bool foundMatch, string ipAddress, string userName, string source, int count, IPAddressEventFlag flag)
        {
            FoundMatch = foundMatch;
            IPAddress = ipAddress;
            UserName = userName;
            Source = source;
            Count = count;
            Flag = flag;
        }

        /// <summary>
        /// Whether a match was found
        /// </summary>
        public bool FoundMatch { get; set; }

        /// <summary>
        /// IP address
        /// </summary>
        public string IPAddress { get; set; }

        /// <summary>
        /// User name
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Source
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// How many messages were aggregated, 1 for no aggregation
        /// </summary>
        public int Count { get; set; }

        /// <summary>
        /// Event flag
        /// </summary>
        public IPAddressEventFlag Flag { get; set; }
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

    /// <summary>
    /// IP address event flags
    /// </summary>
    [Flags]
    public enum IPAddressEventFlag
    {
        /// <summary>
        /// No event
        /// </summary>
        None = 0,

        /// <summary>
        /// Successful login
        /// </summary>
        SuccessfulLogin = 1,

        /// <summary>
        /// Blocked / banned ip address
        /// </summary>
        BlockedIPAddress = 2,

        /// <summary>
        /// Failed login
        /// </summary>
        FailedLogin = 4,
    }
}
