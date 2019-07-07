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
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

#endregion Imports

namespace DigitalRuby.IPBan
{
    public partial class IPBanService
    {
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

        private async Task FirewallTask(AsyncQueue<Func<CancellationToken, Task>> queue)
        {
            while (!firewallQueueCancel.IsCancellationRequested)
            {
                KeyValuePair<bool, Func<CancellationToken, Task>> nextAction = await queue.TryDequeueAsync(firewallQueueCancel.Token);
                if (nextAction.Key && nextAction.Value != null)
                {
                    try
                    {
                        await nextAction.Value.Invoke(firewallQueueCancel.Token);
                    }
                    catch (Exception ex)
                    {
                        IPBanLog.Error(ex);
                    }
                }
            }
        }

        private void UpdateLogFiles(IPBanConfig newConfig)
        {
            // remove existing log files that are no longer in config
            foreach (IPBanLogFileScanner file in logFilesToParse.ToArray())
            {
                if (newConfig.LogFilesToParse.FirstOrDefault(f => f.PathsAndMasks.Contains(file.PathAndMask)) == null)
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
                            Regex.IsMatch(IPBanOS.Description, newFile.PlatformRegex.ToString().Trim(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                        {
                            // log files use a timer internally and do not need to be updated regularly
                            IPBanLogFileScanner scanner = new IPBanIPAddressLogFileScanner(this, DnsLookup,
                                newFile.Source, pathAndMask, newFile.Recursive, newFile.FailedLoginRegex, newFile.SuccessfulLoginRegex, newFile.MaxFileSize, newFile.PingInterval);
                            logFilesToParse.Add(scanner);
                            IPBanLog.Debug("Adding log file to parse: {0}", pathAndMask);
                        }
                        else
                        {
                            IPBanLog.Debug("Ignoring log file path {0}, regex: {1}", pathAndMask, newFile.PlatformRegex);
                        }
                    }
                }
            }
        }

        internal async Task ReadAppSettings()
        {
            try
            {
                ConfigFilePath = (!File.Exists(ConfigFilePath) ? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, IPBanService.ConfigFileName) : ConfigFilePath);
                DateTime lastDateTime = File.GetLastWriteTimeUtc(ConfigFilePath);
                if (lastDateTime > lastConfigFileDateTime)
                {
                    lastConfigFileDateTime = lastDateTime;
                    await configLock.WaitAsync(firewallQueueCancel.Token);
                    try
                    {
                        IPBanConfig newConfig = await IPBanConfig.LoadFromFileAsync(ConfigFilePath, DnsLookup);
                        UpdateLogFiles(newConfig);
                        whitelistChanged = (Config == null || Config.WhiteList != newConfig.WhiteList || Config.WhiteListRegex != newConfig.WhiteListRegex);
                        Config = newConfig;
                    }
                    finally
                    {
                        configLock.Release();
                    }
                    LoadFirewall();
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);

                if (Config == null)
                {
                    throw new ApplicationException("Configuration failed to load, make sure to check for XML errors or unblock all the files.", ex);
                }
            }

            // set or unset default banned ip address handler based on config
            if (Config.UseDefaultBannedIPAddressHandler && BannedIPAddressHandler == null)
            {
                BannedIPAddressHandler = new DefaultBannedIPAddressHandler();
            }
            else if (!Config.UseDefaultBannedIPAddressHandler && BannedIPAddressHandler != null && BannedIPAddressHandler is DefaultBannedIPAddressHandler)
            {
                BannedIPAddressHandler = null;
            }
        }

        private void WhitelistChangedFromDelegate()
        {
            whitelistChanged = true;
        }

        private object BeginTransaction()
        {
            return ipDB.BeginTransaction();
        }

        private void CommitTransaction(object transaction)
        {
            ipDB.CommitTransaction(transaction);
        }

        private void RollbackTransaction(object transaction)
        {
            // if already committed, nothing happens
            ipDB.RollbackTransaction(transaction);
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
                    LocalIPAddressString = DnsLookup.GetLocalIPAddress().Sync()?.ToString();
                    IPBanLog.Info("Local ip address: {0}", LocalIPAddressString);
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

        private async Task ProcessPendingFailedLogins(IEnumerable<IPAddressPendingEvent> ipAddresses)
        {
            List<IPAddressPendingEvent> bannedIpAddresses = new List<IPAddressPendingEvent>();
            object transaction = BeginTransaction();
            try
            {
                foreach (IPAddressPendingEvent failedLogin in ipAddresses)
                {
                    try
                    {
                        string ipAddress = failedLogin.IPAddress;
                        string userName = failedLogin.UserName;
                        string source = failedLogin.Source;
                        if (IsWhitelisted(ipAddress))
                        {
                            IPBanLog.Warn("Login failure, ignoring whitelisted ip address {0}, {1}, {2}", ipAddress, userName, source);
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
                                !Config.IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(userName);
                            int newCount = ipDB.IncrementFailedLoginCount(ipAddress, UtcNow, failedLogin.Count, transaction);
                            IPBanLog.Warn(now, "Login failure: {0}, {1}, {2}, {3}", ipAddress, userName, source, newCount);

                            // if the ip address is black listed or the ip address has reached the maximum failed login attempts before ban, ban the ip address
                            if (configBlacklisted || newCount >= maxFailedLoginAttempts)
                            {
                                if (ipDB.TryGetIPAddressState(ipAddress, out IPBanDB.IPAddressState state, transaction) &&
                                    (state == IPBanDB.IPAddressState.Active || state == IPBanDB.IPAddressState.AddPending))
                                {
                                    IPBanLog.Warn(now, "IP {0}, {1}, {2} ban pending.", ipAddress, userName, source);
                                }
                                else
                                {
                                    IPBanLog.Debug("Failed login count {0} >= ban count {1}{2}", newCount, maxFailedLoginAttempts, (configBlacklisted ? " config blacklisted" : string.Empty));

                                    // if delegate and non-zero count, forward on - count of 0 means it was from external source, like a delegate
                                    if (IPBanDelegate != null && failedLogin.Count > 0)
                                    {
                                        await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, UtcNow);
                                    }
                                    AddBannedIPAddress(ipAddress, source, userName, bannedIpAddresses, now, configBlacklisted, newCount, string.Empty, transaction);
                                }
                            }
                            else
                            {
                                IPBanLog.Debug("Failed login count {0} <= ban count {1}", newCount, maxFailedLoginAttempts);
                                if (IPBanOS.UserIsActive(userName))
                                {
                                    IPBanLog.Warn("Login failed for known active user {0}", userName);
                                }
                                    
                                // if delegate and non-zero count, forward on - count of 0 means it was from external source, like a delegate
                                if (IPBanDelegate != null && failedLogin.Count > 0)
                                {
                                    await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, UtcNow);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        IPBanLog.Error(ex);
                    }
                }
                CommitTransaction(transaction);
                ExecuteExternalProcessForBannedIPAddresses(bannedIpAddresses);
            }
            catch (Exception ex)
            {
                RollbackTransaction(transaction);
                IPBanLog.Error(ex);
            }
        }

        private Task ProcessPendingSuccessfulLogins(IEnumerable<IPAddressPendingEvent> ipAddresses)
        {
            foreach (IPAddressPendingEvent info in ipAddresses)
            {
                IPBanLog.Warn("Login succeeded, address: {0}, user name: {1}, source: {2}", info.IPAddress, info.UserName, info.Source);
            }
            if (IPBanDelegate != null)
            {
                return Task.Run(() =>
                {
                    try
                    {
                        foreach (IPAddressPendingEvent info in ipAddresses)
                        {
                            // pass the success login on
                            IPBanDelegate.LoginAttemptSucceeded(info.IPAddress, info.Source, info.UserName, MachineGuid, OSName, OSVersion, info.DateTime);
                        }
                    }
                    catch (Exception ex)
                    {
                        IPBanLog.Error(ex);
                    }
                });
            }

            return Task.CompletedTask;
        }

        private void ExecuteTask(Task task)
        {
            if (MultiThreaded)
            {
                task.ConfigureAwait(false).GetAwaiter();
            }
            else
            {
                task.Wait();
            }
        }

        private void AddBannedIPAddress(string ipAddress, string source, string userName, List<IPAddressPendingEvent> bannedIpAddresses,
            DateTime startBanDate, bool configBlacklisted, int counter, string extraInfo, object transaction)
        {
            TimeSpan[] banTimes = Config.BanTimes;
            DateTime banEndDate = startBanDate + banTimes.First();
            if (banTimes.Length > 1 && ipDB.TryGetIPAddress(ipAddress, out IPBanDB.IPAddressEntry ipEntry, transaction) && ipEntry.BanStartDate != null && ipEntry.BanEndDate != null)
            {
                // find the next ban time in the array
                TimeSpan span = ipEntry.BanEndDate.Value - ipEntry.BanStartDate.Value;
                for (int i = 0; i < banTimes.Length; i++)
                {
                    if (span < banTimes[i] || banTimes[i].Ticks <= 0)
                    {
                        // ban for 1 year if ticks less than 1
                        banEndDate = startBanDate + (banTimes[i].Ticks <= 0 ? TimeSpan.FromHours(24.0 * 365.0) : banTimes[i]);
                        break;
                    }
                }
            }
            bannedIpAddresses.Add(new IPAddressPendingEvent { IPAddress = ipAddress, Source = source, UserName = userName });
            if (ipDB.SetBanDates(ipAddress, startBanDate, banEndDate, UtcNow, transaction))
            {
                firewallNeedsBlockedIPAddressesUpdate = true;
            }

            // if this is a delegate callback (counter of 0) or no handlers, exit out
            if (counter <= 0 || (BannedIPAddressHandler == null && IPBanDelegate == null))
            {
                return;
            }

            IPBanLog.Warn(startBanDate, "Banning ip address: {0}, user name: {1}, config black listed: {2}, count: {3}, extra info: {4}",
                ipAddress, userName, configBlacklisted, counter, extraInfo);

            if (BannedIPAddressHandler != null && System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj) && !ipAddressObj.IsInternal())
            {
                try
                {
                    ExecuteTask(BannedIPAddressHandler.HandleBannedIPAddress(ipAddress, source, userName, OSName, OSVersion, AssemblyVersion, RequestMaker));
                }
                catch
                {
                }
            }
            if (IPBanDelegate != null)
            {
                try
                {
                    ExecuteTask(IPBanDelegate.IPAddressBanned(ipAddress, source, userName, MachineGuid, OSName, OSVersion, UtcNow, true));
                }
                catch (Exception ex)
                {
                    IPBanLog.Info("Error calling ipban delegate with banned ip address: " + ex.ToString());
                }
            }
        }

        private void ExecuteExternalProcessForBannedIPAddresses(IReadOnlyCollection<IPAddressPendingEvent> bannedIPAddresses)
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
                Firewall.Truncate();
                ipDB.Truncate(true);
            }
            else
            {
                DateTime now = UtcNow;
                DateTime banEnd = now + Config.BanTimes.First();

                IPBanLog.Warn("Syncing firewall and {0} database...", IPBanDB.FileName);

                // bring all firewall ip into the database, if they already exist they will be ignored
                ipDB.SetBannedIPAddresses(Firewall.EnumerateBannedIPAddresses().Select(i => new Tuple<string, DateTime, DateTime>(i, now, banEnd)), UtcNow);

                // remove any rows where the ip address was going to be removed
                ipDB.DeletePendingRemoveIPAddresses();

                // ensure firewall is up to date with all the correct ip addresses, if any ip are in the db but not in the firewall, they will
                // get synced up here
                Firewall.BlockIPAddresses(null, ipDB.EnumerateBannedIPAddresses()).Sync();

                // set firewall update flag, if any deltas are lingering in the db (state = add pending or remove pending) they will get
                // processed on the next cycle
                firewallNeedsBlockedIPAddressesUpdate = true;

                // report on initial count
                int count = ipDB.GetIPAddressCount();
                IPBanLog.Warn("{0} total ip addresses in the {1} database", count, IPBanDB.FileName);
            }
        }

        private void LoadFirewall()
        {
            IIPBanFirewall existing = Firewall;
            Firewall = IPBanFirewallUtility.CreateFirewall(Config.FirewallOSAndType, Config.FirewallRulePrefix, Firewall);
            AddUpdater(Firewall);
            if (existing != Firewall)
            {
                IPBanLog.Warn("Loaded firewall type {0}", Firewall.GetType());
                if (existing != null)
                {
                    RemoveUpdater(existing);

                    // transfer banned ip to new firewall
                    Firewall.BlockIPAddresses(null, ipDB.EnumerateBannedIPAddresses()).Sync();
                }
            }
        }

        private void HandleWhitelistChanged(object transaction, HashSet<string> unbanList)
        {
            // if the whitelist changed, we have no choice but to loop the entire db to remove ip
            // this should not happen very often so not a problem
            if (whitelistChanged)
            {
                whitelistChanged = false;
                foreach (IPBanDB.IPAddressEntry ipAddress in ipDB.EnumerateIPAddresses(null, null, transaction))
                {
                    if (IsWhitelisted(ipAddress.IPAddress))
                    {
                        if (ipAddress.State == IPBanDB.IPAddressState.Active)
                        {
                            IPBanLog.Warn("Un-banning whitelisted ip address {0}", ipAddress.IPAddress);
                            unbanList?.Add(ipAddress.IPAddress);
                            DB.SetIPAddressesState(new string[] { ipAddress.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                            firewallNeedsBlockedIPAddressesUpdate = true;
                        }
                        else
                        {
                            IPBanLog.Warn("Forgetting whitelisted ip address {0}", ipAddress.IPAddress);
                            DB.DeleteIPAddress(ipAddress.IPAddress, transaction);
                        }
                    }
                }
            }
        }

        private void HandleExpiredLoginsAndBans(DateTime failLoginCutOff, DateTime banCutOff, bool allowBanExpire, bool allowFailedLoginExpire,
            object transaction, HashSet<string> unbanList)
        {
            TimeSpan[] banTimes = Config.BanTimes;

            // fast query into database for entries that should be deleted due to un-ban or forgetting failed logins
            foreach (IPBanDB.IPAddressEntry ipAddress in ipDB.EnumerateIPAddresses(failLoginCutOff, banCutOff, transaction))
            {
                // never un-ban a blacklisted entry
                if (Config.IsBlackListed(ipAddress.IPAddress) && !Config.IsWhitelisted(ipAddress.IPAddress))
                {
                    continue;
                }
                // if ban duration has expired, un-ban, check this first as these must trigger a firewall update
                else if (allowBanExpire && ipAddress.State == IPBanDB.IPAddressState.Active && ipAddress.BanStartDate != null && ipAddress.BanEndDate != null)
                {
                    // check gap of ban end date vs ban date and see where we are in the ban times, if we have gone beyond the last ban time,
                    // we need to unban the ip address and remove from db, otherwise the ban end date needs to be increased to the next ban interval and
                    // the ip address needs to be unbanned but turn back into a failed login
                    TimeSpan span = ipAddress.BanEndDate.Value - ipAddress.BanStartDate.Value;
                    int i = banTimes.Length;
                    firewallNeedsBlockedIPAddressesUpdate = true;
                    unbanList?.Add(ipAddress.IPAddress);

                    // if more than one ban time, we have tiered ban times where the ban time increases 
                    if (banTimes.Length > 1)
                    {
                        for (i = 0; i < banTimes.Length; i++)
                        {
                            if (span < banTimes[i] || banTimes[i].Ticks <= 0)
                            {
                                // this is the next span to ban
                                break;
                            }
                        }
                    }
                    if (i < banTimes.Length)
                    {
                        IPBanLog.Warn("Preparing ip address {0} for next ban time {1}", ipAddress.IPAddress, banTimes[i]);
                        ipDB.SetIPAddressesState(new string[] { ipAddress.IPAddress }, IPBanDB.IPAddressState.RemovePendingBecomeFailedLogin, transaction);
                    }
                    else
                    {
                        IPBanLog.Warn("Un-banning ip address {0}, ban expired", ipAddress.IPAddress);
                        ipDB.SetIPAddressesState(new string[] { ipAddress.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                    }
                }
                // if fail login has expired, remove ip address from db
                else if (allowFailedLoginExpire && ipAddress.State == IPBanDB.IPAddressState.FailedLogin)
                {
                    IPBanLog.Warn("Forgetting failed login ip address {0}, time expired", ipAddress.IPAddress);
                    DB.DeleteIPAddress(ipAddress.IPAddress, transaction);
                }
            }
        }

        private async Task UpdateExpiredIPAddressStates()
        {
            HashSet<string> unbanIPAddressesToNotifyDelegate = (IPBanDelegate == null ? null : new HashSet<string>());
            DateTime now = UtcNow;
            DateTime failLoginCutOff = (now - Config.ExpireTime);
            DateTime banCutOff = now;
            bool allowBanExpire = (Config.BanTimes.First().Ticks > 0);
            bool allowFailedLoginExpire = (Config.ExpireTime.Ticks > 0);
            object transaction = DB.BeginTransaction();

            try
            {
                HandleWhitelistChanged(transaction, unbanIPAddressesToNotifyDelegate);
                HandleExpiredLoginsAndBans(failLoginCutOff, banCutOff, allowBanExpire, allowFailedLoginExpire, transaction, unbanIPAddressesToNotifyDelegate);
                ipDB.CommitTransaction(transaction);

                // notify delegate of all unbanned ip addresses
                if (IPBanDelegate != null)
                {
                    foreach (string ip in unbanIPAddressesToNotifyDelegate)
                    {
                        await IPBanDelegate.IPAddressBanned(ip, null, null, MachineGuid, OSName, OSVersion, UtcNow, false);
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
                DB.RollbackTransaction(transaction);
            }
            finally
            {
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

        private async Task UpdateDelegate()
        {
            if (IPBanDelegate == null)
            {
                return;
            }

            try
            {
                // ensure we are notified of whitelist updates
                IPBanDelegate.WhitelistChanged -= WhitelistChangedFromDelegate;
                IPBanDelegate.WhitelistChanged += WhitelistChangedFromDelegate;
                await IPBanDelegate.Update();
            }
            catch (Exception ex)
            {
                IPBanLog.Error("Error in delegate Update", ex);
            }
        }

        protected virtual async Task GetUrl(UrlType urlType)
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
                    KeyValuePair<string, object>[] headers = (Authorization == null ? null : new KeyValuePair<string, object>[] { new KeyValuePair<string, object>("Authorization", Authorization) });
                    byte[] bytes = await RequestMaker.MakeRequestAsync(new Uri(url), headers: headers);
                    if (urlType == UrlType.Start)
                    {
                        gotStartUrl = true;
                    }
                    else if (urlType == UrlType.Update)
                    {
                        // if the update url sends bytes, we assume a software update, and run the result as an .exe
                        if (bytes.Length != 0)
                        {
                            string tempFile = Path.Combine(IPBanOS.TempFolder, "IPBanServiceUpdate.exe");
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
                        await UpdateConfig(Encoding.UTF8.GetString(bytes));
                    }
                }
                catch (Exception ex)
                {
                    IPBanLog.Error(ex, "Error getting url of type {0} at {1}", urlType, url);
                }
            }
        }

        private async Task UpdateUpdaters()
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
                await updater.Update();
            }
        }

        private void UpdateFirewall()
        {
            if (firewallNeedsBlockedIPAddressesUpdate)
            {
                firewallNeedsBlockedIPAddressesUpdate = false;
                List<IPBanFirewallIPAddressDelta> deltas = ipDB.EnumerateIPAddressesDeltaAndUpdateState(true, Config.ResetFailedLoginCountForUnbannedIPAddresses).Where(i => !i.Added || !IsWhitelisted(i.IPAddress)).ToList();
                IPBanLog.Warn("Updating firewall with {0} entries...", deltas.Count);
                IPBanLog.Debug("Firewall entries updated: {0}", string.Join(',', deltas.Select(d => d.IPAddress)));
                if (MultiThreaded)
                {
                    RunFirewallTask((token) => Firewall.BlockIPAddressesDelta(null, deltas, null, token), "Default");
                }
                else
                {
                    Firewall.BlockIPAddressesDelta(null, deltas).Sync();
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
                        cycleTimer.Interval = Math.Min(60000.0, Math.Max(1000.0, Config.CycleTime.TotalMilliseconds));
                        cycleTimer.Start();
                    }
                    catch
                    {
                    }
                }
                IPBanLog.Trace("CycleTimerElapsed");
            }
        }

        private void ProcessIPAddressEvent(IPAddressLogEvent evt, List<IPAddressPendingEvent> pendingEvents, TimeSpan minTimeBetweenEvents, string type)
        {
            if (evt.Count <= 0)
            {
                // callback from somewhere else external
                return;
            }

            evt.Source = (evt.Source ?? "?");
            evt.UserName = (evt.UserName ?? string.Empty);

            lock (pendingEvents)
            {
                IPAddressPendingEvent existing = pendingEvents.FirstOrDefault(p => p.IPAddress == evt.IPAddress && (p.UserName == null || p.UserName == evt.UserName));
                if (existing == null)
                {
                    existing = new IPAddressPendingEvent
                    {
                        IPAddress = evt.IPAddress,
                        Source = evt.Source,
                        UserName = evt.UserName,
                        DateTime = UtcNow,
                        Count = evt.Count
                    };
                    pendingEvents.Add(existing);
                }
                else
                {
                    existing.UserName = (existing.UserName ?? evt.UserName);

                    // if more than n seconds has passed, increment the counter
                    // we don't want to count multiple logs that all map to the same ip address from one failed
                    // attempt to count multiple times if they happen rapidly, if the parsers are parsing the same
                    // failed login that reads many different ways, we don't want to lock out legitimate failed logins
                    if ((UtcNow - existing.DateTime) >= minTimeBetweenEvents)
                    {
                        // update to the latest timestamp of the failed login
                        existing.DateTime = UtcNow;

                        // increment counter
                        existing.Count += evt.Count;
                    }
                    else
                    {
                        IPBanLog.Debug("Ignoring {0} login from {1}, min time between login attempts has not elapsed", type, existing.IPAddress);
                    }
                }
            }
        }

        /// <summary>
        /// Process all pending failed logins
        /// </summary>
        private async Task ProcessPendingFailedLogins()
        {
            ProcessPendingLogEvents();

            // make a quick copy of pending ip addresses so we don't lock it for very long
            List<IPAddressPendingEvent> ipAddresses = null;
            lock (pendingFailedLogins)
            {
                if (pendingFailedLogins.Count != 0)
                {
                    ipAddresses = new List<IPAddressPendingEvent>(pendingFailedLogins);
                    pendingFailedLogins.Clear();
                    IPBanLog.Debug("{0} pending failed logins", pendingFailedLogins.Count);
                }
            }
            if (ipAddresses != null)
            {
                await ProcessPendingFailedLogins(ipAddresses);
            }
            UpdateFirewall();
        }

        /// <summary>
        /// Process all pending successful logins
        /// </summary>
        private async Task ProcessPendingSuccessfulLogins()
        {
            // make a quick copy of pending ip addresses so we don't lock it for very long
            List<IPAddressPendingEvent> ipAddresses = null;
            lock (pendingSuccessfulLogins)
            {
                if (pendingSuccessfulLogins.Count != 0)
                {
                    ipAddresses = new List<IPAddressPendingEvent>(pendingSuccessfulLogins);
                    pendingSuccessfulLogins.Clear();
                }
            }
            if (ipAddresses != null)
            {
                await ProcessPendingSuccessfulLogins(ipAddresses);
            }
        }

        private void ProcessPendingLogEvents()
        {
            // get copy of pending log events quickly in a lock and clear list
            List<IPAddressLogEvent> events;
            lock (pendingLogEvents)
            {
                events = new List<IPAddressLogEvent>(pendingLogEvents);
                pendingLogEvents.Clear();
            }

            List<IPAddressPendingEvent> bannedIPs = new List<IPAddressPendingEvent>();
            object transaction = BeginTransaction();
            try
            {
                foreach (IPAddressLogEvent evt in events)
                {
                    if (!IPBanFirewallUtility.TryNormalizeIPAddress(evt.IPAddress, out string normalizedIPAddress))
                    {
                        continue;
                    }
                    evt.IPAddress = normalizedIPAddress;
                    switch (evt.Type)
                    {
                        case IPAddressEventType.FailedLogin:
                            ProcessIPAddressEvent(evt, pendingFailedLogins, Config.MinimumTimeBetweenFailedLoginAttempts, "failed");
                            break;

                        case IPAddressEventType.SuccessfulLogin:
                            ProcessIPAddressEvent(evt, pendingSuccessfulLogins, Config.MinimumTimeBetweenSuccessfulLoginAttempts, "successful");
                            break;

                        case IPAddressEventType.Blocked:
                            AddBannedIPAddress(evt.IPAddress, evt.Source, evt.UserName, bannedIPs, evt.Timestamp, false, evt.Count, string.Empty, transaction);
                            break;

                        case IPAddressEventType.Unblocked:
                            DB.SetIPAddressesState(new string[] { evt.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                            break;
                    }
                }
                CommitTransaction(transaction);
            }
            catch (Exception ex)
            {
                RollbackTransaction(transaction);
                IPBanLog.Error(ex);
            }
            ExecuteExternalProcessForBannedIPAddresses(bannedIPs);
        }
    }
}
