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
    public class IPBanService : IIPBanService, IHttpRequestMaker
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

        private readonly string configFilePath;
        private Task cycleTask;
        private bool firewallNeedsBlockedIPAddressesUpdate;
        private bool gotStartUrl;

        // note that an ip that has a block count may not yet be in the ipAddressesAndBanDate dictionary
        // for locking, always use ipAddressesAndBanDate
        private readonly Dictionary<string, DateTime> ipAddressesAndBanDate = new Dictionary<string, DateTime>();
        private readonly Dictionary<string, IPBlockCount> ipAddressesAndBlockCounts = new Dictionary<string, IPBlockCount>();
        private readonly ManualResetEvent cycleEvent = new ManualResetEvent(false);
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
                            Regex.IsMatch(RuntimeInformation.OSDescription, newFile.PlatformRegex.Trim(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                        {
                            // log files use a timer internally and do not need to be updated regularly
                            logFilesToParse.Add(new IPBanLogFileScanner(this, newFile.Source, pathAndMask, newFile.Regex, newFile.MaxFileSize, newFile.PingInterval));
                        }
                        else
                        {
                            Log.Write(NLog.LogLevel.Debug, "Ignoring log file {0}", newFile);
                        }
                    }
                }
            }
        }

        internal void ReadAppSettings()
        {
            try
            {
                DateTime lastDateTime = File.GetLastWriteTimeUtc(configFilePath);
                if (lastDateTime > lastConfigFileDateTime)
                {
                    lastConfigFileDateTime = lastDateTime;
                    lock (configLock)
                    {
                        IPBanConfig newConfig = new IPBanConfig(configFilePath);
                        UpdateLogFiles(newConfig);
                        Config = newConfig;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Exception(ex);

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
                    IPAddress[] ips = Dns.GetHostAddresses(Dns.GetHostName());
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
                    byte[] bytes = RequestMaker.DownloadDataAsync(Config.ExternalIPAddressUrl).ConfigureAwait(false).GetAwaiter().GetResult();
                    RemoteIPAddressString = Encoding.UTF8.GetString(bytes).Trim();
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
            Log.Write(NLog.LogLevel.Info, "Whitelist: {0}, Whitelist Regex: {1}", Config.WhiteList, Config.WhiteListRegex);
            Log.Write(NLog.LogLevel.Info, "Blacklist: {0}, Blacklist Regex: {1}", Config.BlackList, Config.BlackListRegex);
        }

        private void ProcessPendingFailedLogins(IEnumerable<FailedLogin> ipAddresses)
        {
            List<KeyValuePair<string, string>> bannedIpAddresses = new List<KeyValuePair<string, string>>();
            foreach (FailedLogin p in ipAddresses)
            {
                try
                {
                    string ipAddress = p.IPAddress;
                    string userName = p.UserName;
                    string source = p.Source;
                    if (Config.IsIPAddressWhitelisted(ipAddress) ||
                        (IPBanDelegate != null && IPBanDelegate.IsIPAddressWhitelisted(ipAddress)))
                    {
                        Log.Write(NLog.LogLevel.Warn, "Ignoring whitelisted ip address {0}, {1}, {2}", ipAddress, userName, source);
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

                        int counter = p.Count;
                        DateTime now = p.DateTime;

                        // check for the target user name for additional blacklisting checks                    
                        IPBlockCount ipBlockCount;
                        bool configBlacklisted = Config.IsBlackListed(ipAddress) ||
                            Config.IsBlackListed(userName) ||
                            !Config.IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(userName) ||
                            (IPBanDelegate != null && IPBanDelegate.IsIPAddressBlacklisted(ipAddress));

                        lock (ipAddressesAndBanDate)
                        {
                            // Get the IPBlockCount, if one exists.
                            if (!ipAddressesAndBlockCounts.TryGetValue(ipAddress, out ipBlockCount))
                            {
                                // This is the first failed login attempt, so record a new IPBlockCount.
                                ipAddressesAndBlockCounts[ipAddress] = ipBlockCount = new IPBlockCount();
                            }

                            // Increment the count.
                            counter = ipBlockCount.IncrementCount(CurrentDateTime, counter);

                            Log.Write(NLog.LogLevel.Info, "Incremented count for ip {0} to {1}, user name: {2}", ipAddress, counter, userName);
                        }

                        // if the ip address is black listed or the ip address has reached the maximum failed login attempts before ban, ban the ip address
                        if (configBlacklisted || ipBlockCount.Count >= maxFailedLoginAttempts)
                        {
                            bool alreadyBanned;
                            lock (ipAddressesAndBanDate)
                            {
                                alreadyBanned = ipAddressesAndBanDate.ContainsKey(ipAddress);
                            }

                            // if the ip address is not already in the ban list, add it and mark it as needing to be banned
                            if (alreadyBanned)
                            {
                                Log.Write(NLog.LogLevel.Info, "IP {0}, {1}, {2} should already be banned, alreadyBanned == true.", ipAddress, userName, source);
                            }
                            else
                            {
                                if (IPBanDelegate != null)
                                {
                                    IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName).ConfigureAwait(false).GetAwaiter().GetResult();
                                }
                                AddBannedIPAddress(ipAddress, source, userName, bannedIpAddresses, now, configBlacklisted, counter, string.Empty);
                            }
                        }
                        else if (ipBlockCount.Count > maxFailedLoginAttempts)
                        {
                            Log.Write(NLog.LogLevel.Info, "IP {0}, {1}, {2} should already be banned.", ipAddress, counter, source);
                        }
                        else
                        {
                            if (IPBanDelegate != null)
                            {
                                LoginFailedResult result = IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName).ConfigureAwait(false).GetAwaiter().GetResult();
                                if (result.HasFlag(LoginFailedResult.Blacklisted))
                                {
                                    AddBannedIPAddress(ipAddress, userName, source, bannedIpAddresses, now, configBlacklisted, ipBlockCount.Count, "Delegate banned ip: " + result);
                                    continue;
                                }
                            }
                            Log.Write(NLog.LogLevel.Warn, "Login attempt failed: {0}, {1}, {2}, {3}", ipAddress, userName, source, counter);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Exception(ex);
                }
            }

            // finish processing of pending banned ip addresses
            if (bannedIpAddresses.Count != 0)
            {
                ProcessBannedIPAddresses(bannedIpAddresses);
            }
        }

        public static string UrlEncode(string text)
        {
            return HttpUtility.UrlEncode(text);
        }

        internal Task SubmitIPAddress(string ipAddress, string source, string userName)
        {
            // submit url to ipban public database so that everyone can benefit from an aggregated list of banned ip addresses
            string timestamp = DateTime.UtcNow.ToString("o");
            string version = Assembly.GetAssembly(typeof(IPBanService)).GetName().Version.ToString();
            string url = $"/IPSubmitBanned?ip={UrlEncode(ipAddress)}&osname={UrlEncode(OSName)}&osversion={UrlEncode(OSVersion)}&source={UrlEncode(source)}&timestamp={UrlEncode(timestamp)}&userName={UrlEncode(userName)}&version={version}";
            string hash = Convert.ToBase64String(new SHA256Managed().ComputeHash(Encoding.UTF8.GetBytes(url + Resources.IPBanKey1)));
            url += "&hash=" + UrlEncode(hash);
            url = "https://api.ipban.com" + url;

            try
            {
                return RequestMaker.DownloadDataAsync(url);
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
            lock (ipAddressesAndBanDate)
            {
                ipAddressesAndBanDate[ipAddress] = dateTime;
            }
            firewallNeedsBlockedIPAddressesUpdate = true;
            Log.Write(NLog.LogLevel.Warn, "Banning ip address: {0}, user name: {1}, config black listed: {2}, count: {3}, extra info: {4}",
                ipAddress, userName, configBlacklisted, counter, extraInfo);

            if (!IsTesting)
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
                            Log.Exception("Failed to execute process on ban", ex);
                        }
                    }
                    try
                    {
                        IPBanDelegate?.IPAddressBanned(bannedIp.Key, bannedIp.Value, true);
                    }
                    catch (Exception ex)
                    {
                        Log.Exception("Error in delegate IPAddressBanned", ex);
                    }
                }
            });
        }

        private void UpdateBannedIPAddressesOnStart()
        {
            ipAddressesAndBlockCounts.Clear();
            ipAddressesAndBanDate.Clear();
            if (Config.ClearBannedIPAddressesOnRestart)
            {
                Log.Write(NLog.LogLevel.Warn, "Clearing all banned ip addresses on start because ClearBannedIPAddressesOnRestart is set");
                Firewall.BlockIPAddresses(new string[0]);
            }
            else
            {
                // create an in memory ban list from every ip address in the firewall
                DateTime now = CurrentDateTime;
                foreach (string ipAddress in Firewall.EnumerateBannedIPAddresses())
                {
                    ipAddressesAndBanDate[ipAddress] = now;
                }
                Log.Write(NLog.LogLevel.Warn, "Loaded {0} banned ip addresses", ipAddressesAndBanDate.Count);
            }
        }

        private void Initialize()
        {
            IsRunning = true;

            // find the first firewall implementation if the firewall is null
            if (Firewall == null)
            {
                Type firewallType = typeof(IIPBanFirewall);
                var q =
                    from a in AppDomain.CurrentDomain.GetAssemblies().SelectMany(a => a.GetTypes())
                    where a != firewallType && firewallType.IsAssignableFrom(a) &&
                        (a.GetCustomAttribute<RequiredOperatingSystemAttribute>() == null || a.GetCustomAttribute<RequiredOperatingSystemAttribute>().IsValid)
                    select a;
                foreach (Type t in q)
                {
                    Firewall = Activator.CreateInstance(t) as IIPBanFirewall;
                    break;
                }
            }
            if (Firewall == null)
            {
                throw new ArgumentException("Firewall is null, at least one type should implement IIPBanFirewall");
            }
            OSName = IPBanOS.Name + " (" + IPBanOS.FriendlyName + ")";
            OSVersion = IPBanOS.Version;
            ReadAppSettings();
            Firewall.Initialize(string.IsNullOrWhiteSpace(Config.RuleName) ? "IPBan_BlockIPAddresses_" : Config.RuleName);
            UpdateBannedIPAddressesOnStart();
            LogInitialConfig();
            IPBanDelegate?.Start(this);
            Log.Write(NLog.LogLevel.Warn, "IPBan service started and initialized. Operating System: {0}", IPBanOS.OSString());
        }

        private void CheckForExpiredIP()
        {
            List<string> ipAddressesToForget = new List<string>();
            KeyValuePair<string, DateTime>[] blockList;
            KeyValuePair<string, IPBlockCount>[] ipBlockCountList;

            // brief lock, we make copies of everything and work on the copies so we don't hold a lock too long
            lock (ipAddressesAndBanDate)
            {
                blockList = ipAddressesAndBanDate.ToArray();
            }

            DateTime now = CurrentDateTime;

            // Check the block list for expired IPs.
            foreach (KeyValuePair<string, DateTime> keyValue in blockList)
            {
                // never un-ban a blacklisted entry
                if (Config.IsBlackListed(keyValue.Key))
                {
                    continue;
                }
                // if ban duration has expired or ip is white listed, un-ban
                else if ((Config.BanTime.Ticks > 0 && (now - keyValue.Value) > Config.BanTime) || Config.IsIPAddressWhitelisted(keyValue.Key))
                {
                    Log.Write(NLog.LogLevel.Warn, "Un-banning ip address {0}", keyValue.Key);
                    lock (ipAddressesAndBanDate)
                    {
                        // take the ip out of the lists and mark the file as changed so that the ban script re-runs without this ip
                        ipAddressesAndBanDate.Remove(keyValue.Key);
                        ipAddressesAndBlockCounts.Remove(keyValue.Key);
                        firewallNeedsBlockedIPAddressesUpdate = true;
                    }
                }
            }

            lock (ipAddressesAndBanDate)
            {
                ipBlockCountList = ipAddressesAndBlockCounts.ToArray();
            }

            // if we are allowing ip addresses failed login attempts to expire and get reset back to 0
            if (Config.ExpireTime.TotalSeconds > 0)
            {
                // Check the list of failed login attempts, that are not yet blocked, for expired IPs.
                foreach (KeyValuePair<string, IPBlockCount> keyValue in ipBlockCountList)
                {
                    if (Config.IsBlackListed(keyValue.Key))
                    {
                        continue;
                    }

                    // Find this IP address in the block list.
                    var block = from b in blockList
                                where b.Key == keyValue.Key
                                select b;

                    // If this IP is not yet blocked, and an invalid login attempt has not been made in the past timespan, see if we should forget it.
                    if (block.Count() == 0)
                    {
                        TimeSpan elapsed = (now - keyValue.Value.LastFailedLogin);
                        if (elapsed > Config.ExpireTime)
                        {
                            Log.Write(NLog.LogLevel.Info, "Forgetting ip address {0}", keyValue.Key);
                            ipAddressesToForget.Add(keyValue.Key);

                            // no need to set firewall update here, it is just resetting failed login attempts before a ban
                        }
                    }
                }

                // Remove the IPs that have expired.
                lock (ipAddressesAndBanDate)
                {
                    foreach (string ip in ipAddressesToForget)
                    {
                        // no need to mark the firewall as changed because this ip was not banned, it only had some number of failed login attempts
                        ipAddressesAndBlockCounts.Remove(ip);
                    }
                }

                // notify delegate outside of lock
                if (IPBanDelegate != null)
                {
                    // notify delegate of unban in background thread
                    RunTask(() =>
                    {
                        foreach (string ip in ipAddressesToForget)
                        {
                            try
                            {
                                IPBanDelegate.IPAddressBanned(ip, null, false);
                            }
                            catch (Exception ex)
                            {
                                Log.Exception("Error in delegate IPAddressBanned", ex);
                            }
                        }
                    });
                }
            }
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
                    lock (ipAddressesAndBanDate)
                    {
                        foreach (string ip in IPBanDelegate.EnumerateBlackList())
                        {
                            // ban all blacklisted ip addresses from the delegate
                            // this can be used to sync bans from other machines
                            if (!ipAddressesAndBanDate.ContainsKey(ip))
                            {
                                ipAddressesAndBanDate[ip] = now;
                                ipAddressesAndBlockCounts.Remove(ip);
                                firewallNeedsBlockedIPAddressesUpdate = true;
                            }
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
                            if (ipAddressesAndBanDate.ContainsKey(ip))
                            {
                                ipAddressesAndBanDate.Remove(ip);
                                ipAddressesAndBlockCounts.Remove(ip);
                                firewallNeedsBlockedIPAddressesUpdate = true; // next loop will update the firewall
                            }
                            // check for subnet matches, unban any ip from the local subnet
                            else if (ip.Contains('/'))
                            {
                                foreach (string key in ipAddressesAndBanDate.Keys.ToArray())
                                {
                                    if (IpAddressIsInRange(key, ip))
                                    {
                                        ipAddressesAndBanDate.Remove(ip);
                                        ipAddressesAndBlockCounts.Remove(ip);
                                        firewallNeedsBlockedIPAddressesUpdate = true; // next loop will update the firewall
                                    }
                                }
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
            }
            catch (Exception ex)
            {
                Log.Exception("Error in delegate Update", ex);
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
                Assembly a = IPBanService.GetIPBanAssembly();
                url = url.Replace("###IPADDRESS###", IPBanService.UrlEncode(LocalIPAddressString))
                    .Replace("###MACHINENAME###", IPBanService.UrlEncode(FQDN))
                    .Replace("###VERSION###", IPBanService.UrlEncode(a.GetName().Version.ToString()))
                    .Replace("###GUID###", IPBanService.UrlEncode(MachineGuid))
                    .Replace("###OSNAME###", IPBanService.UrlEncode(OSName))
                    .Replace("###OSVERSION###", IPBanService.UrlEncode(OSVersion));
                RunTask(() =>
                {
                    try
                    {
                        byte[] bytes = RequestMaker.DownloadDataAsync(url).ConfigureAwait(false).GetAwaiter().GetResult();
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
                        Log.Exception(ex, "Error getting url of type {0} at {1}", urlType, url);
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

                string[] ipAddresses;

                // quickly copy out data in a lock
                lock (ipAddressesAndBanDate)
                {
                    ipAddresses = ipAddressesAndBanDate.Keys.ToArray();
                }

                if (!IsTesting)
                {
                    // re-create rules for all banned ip addresses
                    Firewall.BlockIPAddresses(ipAddresses);
                }
            }

            // update firewall if needed
            if (ipAddressesToAllowInFirewallNeedsUpdate)
            {
                ipAddressesToAllowInFirewallNeedsUpdate = false;

                // quickly copy out data in a lock
                string[] ipAddresses;
                lock (ipAddressesAndBanDate)
                {
                    ipAddresses = ipAddressesToAllowInFirewall.ToArray();
                }

                if (!IsTesting)
                {
                    // re-create rules for all allowed ip addresses
                    Firewall.AllowIPAddresses(ipAddresses);
                }
            }
        }

        private void CycleTask()
        {
            System.Diagnostics.Stopwatch timer = new Stopwatch();
            while (IsRunning)
            {
                try
                {
                    timer.Restart();
                    RunCycle();
                    TimeSpan nextWait = Config.CycleTime - timer.Elapsed;
                    if (nextWait.TotalMilliseconds < 1.0)
                    {
                        nextWait = TimeSpan.FromMilliseconds(1.0);
                    }
                    cycleEvent.WaitOne(nextWait);
                }
                catch (Exception ex)
                {
                    // should not get here, but if we do log it and sleep a bit in case of repeating error
                    Log.Exception(ex);
                    Thread.Sleep(5000);
                }
            }
        }

        /// <summary>
        /// Create an IPBanService by searching all types in all assemblies
        /// </summary>
        /// <param name="instanceType">The type of service to create</param>
        /// <returns></returns>
        public static IPBanService CreateService(Type instanceType = null)
        {
            Type ipBanServiceRootType = typeof(IPBanService);
            if (instanceType == null)
            {
                foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies())
                {
                    System.Type[] types = a.GetTypes();
                    foreach (Type aType in types)
                    {
                        if ((instanceType != null && aType.IsSubclassOf(instanceType)) ||
                            (instanceType == null && aType == ipBanServiceRootType) ||
                            aType.IsSubclassOf(ipBanServiceRootType))
                        {
                            instanceType = aType;
                            break;
                        }
                    }
                }
                if (instanceType == null)
                {
                    throw new ArgumentException("Unable to find a subclass of " + ipBanServiceRootType.FullName);
                }
            }
            else if (instanceType != ipBanServiceRootType && !instanceType.IsSubclassOf(ipBanServiceRootType))
            {
                throw new ArgumentException("Instance type must be a subclass of " + ipBanServiceRootType.FullName);
            }
            return (IPBanService)Activator.CreateInstance(instanceType, string.Empty);
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
        public void AddFailedLogin(string ipAddress, string source, string userName)
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
                    existing = new FailedLogin { IPAddress = ipAddress, Source = source, UserName = userName, DateTime = CurrentDateTime, Count = 1 };
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
                        existing.Count++;
                    }
                }
            }
        }

        /// <summary>
        /// Get an ip address and user name out of text using regex
        /// </summary>
        /// <param name="regex">Regex</param>
        /// <param name="text">Text</param>
        /// <param name="ipAddress">Found ip address or null if none</param>
        /// <param name="userName">Found user name or null if none</param>
        /// <returns>True if a regex match was found, false otherwise</returns>
        public static bool GetIPAddressAndUserNameFromRegex(Regex regex, string text, ref string ipAddress, ref string userName)
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
                        Log.Write(NLog.LogLevel.Info, "Parsing as IP failed, checking dns '{0}'", tempIPAddress);
                        try
                        {
                            IPHostEntry entry = Dns.GetHostEntry(tempIPAddress);
                            if (entry != null && entry.AddressList != null && entry.AddressList.Length > 0)
                            {
                                ipAddress = entry.AddressList.FirstOrDefault().ToString();
                                Log.Write(NLog.LogLevel.Info, "Dns result '{0}' = '{1}'", tempIPAddress, ipAddress);
                                foundMatch = true;
                                break;
                            }
                        }
                        catch
                        {
                            Log.Write(NLog.LogLevel.Info, "Parsing as dns failed '{0}'", tempIPAddress);
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
                string text = File.ReadAllText(configFilePath);

                // if the file changed, update it
                if (text != xml)
                {
                    lock (configLock)
                    {
                        File.WriteAllText(configFilePath, xml);
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
            cycleEvent.Set();
            cycleTask?.Wait();
            cycleEvent.Dispose();
            GetUrl(UrlType.Stop);
            try
            {
                IPBanDelegate?.Stop();
                IPBanDelegate?.Dispose();
            }
            catch
            {
            }
            IPBanDelegate = null;
            lock (updaters)
            {
                foreach (IUpdater updater in updaters.ToArray())
                {
                    updater.Dispose();
                }
                updaters.Clear();
            }
            foreach (IPBanLogFileScanner file in logFilesToParse)
            {
                file.Dispose();
            }
            logFilesToParse.Clear();
            Log.Write(NLog.LogLevel.Warn, "Stopped IPBan service");
        }

        /// <summary>
        /// Initialize and start the service
        /// </summary>
        public void Start()
        {
            Initialize();
            if (!ManualCycle)
            {
                cycleTask = Task.Run((Action)CycleTask);
            }
        }

        /// <summary>
        /// Calls Dispose
        /// </summary>
        public void Stop()
        {
            Dispose();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configFilePath">Config file path or null for default</param>
        public IPBanService(string configFilePath = null)
        {
            this.configFilePath = (string.IsNullOrWhiteSpace(configFilePath) ?
                ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath :
                configFilePath);
            RequestMaker = this;
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
            result = default(T);
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
        /// Implementation of IHttpRequestMaker
        /// </summary>
        /// <param name="url">Url</param>
        /// <returns>Task of bytes</returns>
        async Task<byte[]> IHttpRequestMaker.DownloadDataAsync(string url)
        {
            using (WebClient client = new WebClient())
            {
                Assembly a = (Assembly.GetEntryAssembly() ?? IPBanService.GetIPBanAssembly());
                client.UseDefaultCredentials = true;
                client.Headers["User-Agent"] = a.GetName().Name;
                return await client.DownloadDataTaskAsync(url);
            }
        }

        /// <summary>
        /// Http request maker, defaults to this
        /// </summary>
        public IHttpRequestMaker RequestMaker { get; set; }

        /// <summary>
        /// The firewall implementation - this will auto-detect if not set
        /// </summary>
        public IIPBanFirewall Firewall { get; set; }

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
        
        private DateTime currentDateTime;
        /// <summary>
        /// Allows changing the current date time to facilitate testing of behavior over elapsed times
        /// </summary>
        public DateTime CurrentDateTime
        {
            get { return currentDateTime == default(DateTime) ? DateTime.UtcNow : currentDateTime; }
            set { currentDateTime = value; }
        }

        /// <summary>
        /// Whether the service is currently running
        /// </summary>
        public bool IsRunning { get; set; }

        /// <summary>
        /// Whether the service is being tested with mock data
        /// </summary>
        public bool IsTesting { get; set; }
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
