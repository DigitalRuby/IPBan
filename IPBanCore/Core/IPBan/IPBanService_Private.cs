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
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#endregion Imports

namespace DigitalRuby.IPBanCore
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
            while (!CancelToken.IsCancellationRequested)
            {
                KeyValuePair<bool, Func<CancellationToken, Task>> nextAction = await queue.TryDequeueAsync(CancelToken);
                if (nextAction.Key && nextAction.Value != null)
                {
                    try
                    {
                        await nextAction.Value.Invoke(CancelToken);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex);
                    }
                }
            }
        }
        
        internal async Task UpdateConfiguration()
        {
            try
            {
                ConfigFilePath = (!File.Exists(ConfigFilePath) ? Path.Combine(AppContext.BaseDirectory, IPBanConfig.DefaultFileName) : ConfigFilePath);
                string newXml = await ConfigReaderWriter.CheckForConfigChange();
                if (!string.IsNullOrWhiteSpace(newXml))
                {
                    IPBanConfig oldConfig = Config;
                    IPBanConfig newConfig = IPBanConfig.LoadFromXml(newXml, DnsLookup, DnsList);
                    ConfigChanged?.Invoke(newConfig);
                    whitelistChanged = (Config is null || Config.Whitelist != newConfig.Whitelist || Config.WhitelistRegex != newConfig.WhitelistRegex);
                    Config = newConfig;
                    LoadFirewall(oldConfig);
                    ParseAndAddUriFirewallRules(newConfig);
                    Logger.Info("Config file changed");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
            }

            if (Config is null)
            {
                throw new ApplicationException("Configuration failed to load, make sure to check for XML errors or unblock all the files.");
            }
            if (Firewall is null)
            {
                throw new ApplicationException("Firewall failed to load, check that your firewall is enabled and setup in configuration properly");
            }

            // set or unset default banned ip address handler based on config
            if (Config.UseDefaultBannedIPAddressHandler && BannedIPAddressHandler is null)
            {
                BannedIPAddressHandler = new DefaultBannedIPAddressHandler();
            }
            else if (!Config.UseDefaultBannedIPAddressHandler && BannedIPAddressHandler != null && BannedIPAddressHandler is DefaultBannedIPAddressHandler)
            {
                BannedIPAddressHandler = NullBannedIPAddressHandler.Instance;
            }

            // will only execute once
            UpdateBannedIPAddressesOnStart();

            // will only execute once
            SetupWindowsEventViewer();
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
                    FQDN = await DnsLookup.GetHostNameAsync();
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
                    LocalIPAddressString = (await DnsLookup.GetLocalIPAddressesAsync()).FirstOrDefault()?.ToString();
                    Logger.Info("Local ip address: {0}", LocalIPAddressString);
                }
                catch
                {
                    // sometimes dns will fail, there is nothing that can be done, don't bother logging
                }
            }

            if (string.IsNullOrWhiteSpace(RemoteIPAddressString))
            {
                try
                {
                    IPAddress ipAddress = await ExternalIPAddressLookup.LookupExternalIPAddressAsync(RequestMaker, Config.ExternalIPAddressUrl);
                    RemoteIPAddressString = ipAddress.ToString();
                    Logger.Info("Remote ip address: {0}", RemoteIPAddressString);
                }
                catch
                {
                    // sometimes ip check url will fail, there is nothing that can be done, don't bother logging
                }
            }

            // request new config file
            await GetUrl(UrlType.Config);
        }

        private async Task ProcessPendingFailedLogins(IReadOnlyList<IPAddressLogEvent> ipAddresses)
        {
            List<IPAddressLogEvent> bannedIpAddresses = new List<IPAddressLogEvent>();
            object transaction = BeginTransaction();
            try
            {
                foreach (IPAddressLogEvent failedLogin in ipAddresses)
                {
                    try
                    {
                        string ipAddress = failedLogin.IPAddress;
                        string userName = failedLogin.UserName;
                        string source = failedLogin.Source;
                        if (IsWhitelisted(ipAddress))
                        {
                            Logger.Warn("Login failure, ignoring whitelisted ip address {0}, {1}, {2}", ipAddress, userName, source);
                        }
                        else
                        {
                            int maxFailedLoginAttempts;
                            if (Config.IsWhitelisted(userName))
                            {
                                maxFailedLoginAttempts = Config.FailedLoginAttemptsBeforeBanUserNameWhitelist;
                            }
                            else
                            {
                                maxFailedLoginAttempts = Config.FailedLoginAttemptsBeforeBan;
                            }

                            DateTime now = failedLogin.Timestamp;

                            // check for the target user name for additional blacklisting checks
                            bool ipBlacklisted = Config.IsBlackListed(ipAddress);
                            bool userBlacklisted = (ipBlacklisted ? false : Config.IsBlackListed(userName));
                            bool userFailsWhitelistRegex = (userBlacklisted ? false : Config.UserNameFailsUserNameWhitelistRegex(userName));
                            bool editDistanceBlacklisted = (ipBlacklisted || userBlacklisted || userFailsWhitelistRegex ? false : !Config.IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(userName));
                            bool configBlacklisted = ipBlacklisted || userBlacklisted || userFailsWhitelistRegex || editDistanceBlacklisted;

                            // if the event came in with a count of 0 that means it is an automatic ban
                            int incrementCount = (failedLogin.Count < 1 ? maxFailedLoginAttempts : failedLogin.Count);
                            int newCount = ipDB.IncrementFailedLoginCount(ipAddress, userName, source, UtcNow, incrementCount, transaction);

                            Logger.Warn(now, "Login failure: {0}, {1}, {2}, {3}", ipAddress, userName, source, newCount);

                            // if the ip address is black listed or the ip address has reached the maximum failed login attempts before ban, ban the ip address
                            if (configBlacklisted || newCount >= maxFailedLoginAttempts)
                            {
                                Logger.Info("IP blacklisted: {0}, user name blacklisted: {1}, fails user name white list regex: {2}, user name edit distance blacklisted: {3}",
                                    ipBlacklisted, userBlacklisted, userFailsWhitelistRegex, editDistanceBlacklisted);

                                if (ipDB.TryGetIPAddressState(ipAddress, out IPBanDB.IPAddressState? state, transaction) &&
                                    (state.Value == IPBanDB.IPAddressState.Active || state.Value == IPBanDB.IPAddressState.AddPending))
                                {
                                    Logger.Warn(now, "IP {0}, {1}, {2} ban pending.", ipAddress, userName, source);
                                }
                                else
                                {
                                    Logger.Debug("Failed login count {0} >= ban count {1}{2}", newCount, maxFailedLoginAttempts, (configBlacklisted ? " config blacklisted" : string.Empty));

                                    // if delegate and non-zero count, forward on - count of 0 means it was from external source, like a delegate
                                    if (IPBanDelegate != null && !failedLogin.External)
                                    {
                                        await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, UtcNow);
                                    }
                                    AddBannedIPAddress(ipAddress, source, userName, bannedIpAddresses, now,
                                        configBlacklisted, newCount, string.Empty, transaction, false);
                                }
                            }
                            else
                            {
                                Logger.Debug("Failed login count {0} <= ban count {1}", newCount, maxFailedLoginAttempts);
                                if (OSUtility.UserIsActive(userName))
                                {
                                    Logger.Warn("Login failed for known active user {0}", userName);
                                }

                                // if delegate and non-zero count, forward on - count of 0 means it was from external source, like a delegate
                                if (IPBanDelegate != null && !failedLogin.External)
                                {
                                    await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, UtcNow);
                                }
                            }
                        }
                    }
      catch (Exception ex)
                    {
                        Logger.Error(ex);
                    }
                }
                CommitTransaction(transaction);
                ExecuteExternalProcessForBannedIPAddresses(bannedIpAddresses);
            }
            catch (Exception ex)
            {
                RollbackTransaction(transaction);
                Logger.Error(ex);
            }
        }

        private Task ProcessPendingSuccessfulLogins(IEnumerable<IPAddressLogEvent> ipAddresses)
        {
            foreach (IPAddressLogEvent info in ipAddresses)
            {
                Logger.Warn("Login succeeded, address: {0}, user name: {1}, source: {2}", info.IPAddress, info.UserName, info.Source);
                if (Config.ClearFailedLoginsOnSuccessfulLogin)
                {
                    DB.DeleteIPAddress(info.IPAddress);
                }
            }
            if (IPBanDelegate != null)
            {
                return Task.Run(() =>
                {
                    try
                    {
                        foreach (IPAddressLogEvent info in ipAddresses)
                        {
                            // pass the success login on
                            IPBanDelegate.LoginAttemptSucceeded(info.IPAddress, info.Source, info.UserName, MachineGuid, OSName, OSVersion, info.Timestamp);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex);
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

        private void AddBannedIPAddress(string ipAddress, string source, string userName, List<IPAddressLogEvent> bannedIpAddresses,
            DateTime startBanDate, bool configBlacklisted, int counter, string extraInfo, object transaction,
            bool external)
        {
            // never ban whitelisted ip addresses
            if (IsWhitelisted(ipAddress))
            {
                Logger.Info("Ignoring ban request for whitelisted ip address {0}", ipAddress);
                return;
            }

            TimeSpan[] banTimes = Config.BanTimes;
            TimeSpan banTime = banTimes.First();
            DateTime banEndDate = startBanDate + banTime;

            // if we have an ip in the database, use the ban time to move to the next ban slot in the list of ban times
            // if ban times only has one entry, do not do this
            if (banTimes.Length > 1 &&
                ipDB.TryGetIPAddress(ipAddress, out IPBanDB.IPAddressEntry ipEntry, transaction) &&
                ipEntry.BanStartDate != null && ipEntry.BanEndDate != null)
            {
                // find the next ban time in the array
                banTime = ipEntry.BanEndDate.Value - ipEntry.BanStartDate.Value;
                for (int i = 0; i < banTimes.Length; i++)
                {
                    if (banTime < banTimes[i])
                    {
                        // ban for next timespan
                        banTime = banTimes[i];
                        banEndDate = startBanDate + banTime;
                        Logger.Info("Moving to next ban duration {0} at index {1} for ip {1}", banTimes[i], i, ipAddress);
                        break;
                    }
                }
            }
            int adjustedCount = (counter <= 0 ? Config.FailedLoginAttemptsBeforeBan : counter);
            bannedIpAddresses?.Add(new IPAddressLogEvent(ipAddress, userName, source, adjustedCount, IPAddressEventType.Blocked));
            if (ipDB.SetBanDates(ipAddress, startBanDate, banEndDate, UtcNow, transaction))
            {
                firewallNeedsBlockedIPAddressesUpdate = true;
            }

            Logger.Warn(startBanDate, "Banning ip address: {0}, user name: {1}, config black listed: {2}, count: {3}, extra info: {4}, duration: {5}",
                ipAddress, userName, configBlacklisted, counter, extraInfo, banTime);

            // if this is a delegate callback (counter of 0), exit out - we don't want to run handlers or processes for shared banned ip addresses
            if (counter <= 0)
            {
                return;
            }
            else if (BannedIPAddressHandler != null &&
                System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj) &&
                !ipAddressObj.IsInternal())
            {
                try
                {
                    ExecuteTask(BannedIPAddressHandler.HandleBannedIPAddress(ipAddress, source, userName, OSName, OSVersion, AssemblyVersion, RequestMaker));
                }
                catch
                {
                    // eat exception, delicious
                }
            }

            if (IPBanDelegate != null && !external)
            {
                try
                {
                    ExecuteTask(IPBanDelegate.IPAddressBanned(ipAddress, source, userName, MachineGuid, OSName, OSVersion, UtcNow, true));
                }
                catch (Exception ex)
                {
                    Logger.Info("Error calling ipban delegate with banned ip address: " + ex.ToString());
                }
            }
        }

        private void ExecuteExternalProcessForBannedIPAddresses(IReadOnlyCollection<IPAddressLogEvent> bannedIPAddresses)
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
                                string program = Path.GetFullPath(pieces[0]);
                                string arguments = pieces[1].Replace("###IPADDRESS###", bannedIp.IPAddress)
                                    .Replace("###SOURCE###", bannedIp.Source)
                                    .Replace("###USERNAME###", bannedIp.UserName);
                                ProcessStartInfo psi = new ProcessStartInfo
                                {
                                    FileName = program,
                                    WorkingDirectory = Path.GetDirectoryName(program),
                                    Arguments = arguments
                                };
                                Process.Start(psi);
                            }
                            else
                            {
                                throw new ArgumentException("Invalid config option for process to run on ban: " + programToRunConfigString);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error("Failed to execute process on ban", ex);
                        }
                    }
                }
            });
        }

        private void UpdateBannedIPAddressesOnStart()
        {
            if (updateBannedIPAddressesOnStartCalled)
            {
                return;
            }
            updateBannedIPAddressesOnStartCalled = true;

            if (Config.ClearBannedIPAddressesOnRestart)
            {
                Logger.Warn("Clearing all banned ip addresses on start because ClearBannedIPAddressesOnRestart is set");
                Firewall.Truncate();
                ipDB.Truncate(true);
            }
            else
            {
                DateTime now = UtcNow;
                DateTime banEnd = now + Config.BanTimes.First();

                Logger.Warn("Syncing firewall and {0} database...", IPBanDB.FileName);

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
                Logger.Warn("{0} total ip addresses in the {1} database", count, IPBanDB.FileName);
            }
        }

        private void LoadFirewall(IPBanConfig oldConfig)
        {
            IIPBanFirewall existing = Firewall;
            Firewall = FirewallCreator.CreateFirewall(Config, Firewall);
            if (existing != Firewall)
            {
                AddUpdater(Firewall);
                Logger.Warn("Loaded firewall type {0}", Firewall.GetType());
                if (existing != null)
                {
                    RemoveUpdater(existing);

                    // transfer banned ip to new firewall
                    Firewall.BlockIPAddresses(null, ipDB.EnumerateBannedIPAddresses()).Sync();
                }
            }

            if (oldConfig is null)
            {
                // clear out all previous custom rules
                foreach (string rule in Firewall.GetRuleNames(Firewall.RulePrefix + "EXTRA_").ToArray())
                {
                    Firewall.DeleteRule(rule);
                }
            }
            else
            {
                // check for updated / new / removed block rules
                List<string> deleteList = new List<string>(oldConfig.ExtraRules.Select(r => r.Name));

                // cleanup rules that are no longer in the config
                foreach (string newRule in Config.ExtraRules.Select(r => r.Name))
                {
                    deleteList.Remove(newRule);
                }
                foreach (string rule in deleteList)
                {
                    foreach (string ruleName in Firewall.GetRuleNames(rule).ToArray())
                    {
                        Firewall.DeleteRule(ruleName);
                    }
                }
            }

            // add/update global rules
            Firewall.AllowIPAddresses("GlobalWhitelist", Config.Whitelist);
            Firewall.BlockIPAddresses("GlobalBlacklist", Config.BlackList);

            // add/update user specified rules
            foreach (IPBanFirewallRule rule in Config.ExtraRules)
            {
                if (rule.Block)
                {
                    Firewall.BlockIPAddresses(rule.Name, rule.IPAddressRanges, rule.AllowPortRanges);
                }
                else
                {
                    Firewall.AllowIPAddresses(rule.Name, rule.IPAddressRanges, rule.AllowPortRanges);
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
                            Logger.Warn("Un-banning whitelisted ip address {0}", ipAddress.IPAddress);
                            unbanList?.Add(ipAddress.IPAddress);
                            DB.SetIPAddressesState(new string[] { ipAddress.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                            firewallNeedsBlockedIPAddressesUpdate = true;
                        }
                        else
                        {
                            Logger.Warn("Forgetting whitelisted ip address {0}", ipAddress.IPAddress);
                            DB.DeleteIPAddress(ipAddress.IPAddress, transaction);
                        }
                    }
                }
            }
        }

        private void HandleExpiredLoginsAndBans(DateTime failLoginCutOff, DateTime banCutOff, object transaction, HashSet<string> unbanList)
        {
            TimeSpan[] banTimes = Config.BanTimes;

            // fast query into database for entries that should be deleted due to un-ban or forgetting failed logins
            foreach (IPBanDB.IPAddressEntry ipAddress in ipDB.EnumerateIPAddresses(failLoginCutOff, banCutOff, transaction))
            {
                // never un-ban a blacklisted entry
                if (Config.IsBlackListed(ipAddress.IPAddress) && !Config.IsWhitelisted(ipAddress.IPAddress))
                {
                    Logger.Debug("Not unbanning blacklisted ip {0}", ipAddress.IPAddress);
                    continue;
                }
                // if ban duration has expired, un-ban, check this first as these must trigger a firewall update
                else if (ipAddress.State == IPBanDB.IPAddressState.Active && ipAddress.BanStartDate != null && ipAddress.BanEndDate != null)
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
                            if (span < banTimes[i])
                            {
                                // this is the next span to ban
                                Logger.Info("Ban duration {0} at index {1} expired for ip {2}", banTimes[i], i, ipAddress);
                                break;
                            }
                        }
                    }
                    if (i < banTimes.Length)
                    {
                        Logger.Warn("Preparing ip address {0} for next ban time {1}", ipAddress.IPAddress, banTimes[i]);
                        ipDB.SetIPAddressesState(new string[] { ipAddress.IPAddress }, IPBanDB.IPAddressState.RemovePendingBecomeFailedLogin, transaction);
                    }
                    else
                    {
                        Logger.Warn("Un-banning ip address {0}, ban expired", ipAddress.IPAddress);
                        ipDB.SetIPAddressesState(new string[] { ipAddress.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                    }
                }
                // if fail login has expired, remove ip address from db
                else if (ipAddress.State == IPBanDB.IPAddressState.FailedLogin)
                {
                    Logger.Warn("Forgetting failed login ip address {0}, time expired", ipAddress.IPAddress);
                    DB.DeleteIPAddress(ipAddress.IPAddress, transaction);
                }
            }
        }

        private async Task UpdateExpiredIPAddressStates()
        {
            HashSet<string> unbanIPAddressesToNotifyDelegate = (IPBanDelegate is null ? null : new HashSet<string>());
            DateTime now = UtcNow;
            DateTime failLoginCutOff = (now - Config.ExpireTime);
            DateTime banCutOff = now;
            object transaction = DB.BeginTransaction();
            try
            {
                HandleWhitelistChanged(transaction, unbanIPAddressesToNotifyDelegate);
                HandleExpiredLoginsAndBans(failLoginCutOff, banCutOff, transaction, unbanIPAddressesToNotifyDelegate);

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
                Logger.Error(ex);
                DB.RollbackTransaction(transaction);
            }
            finally
            {
                DB.CommitTransaction(transaction);
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
            IIPBanDelegate delg = IPBanDelegate;
            if (delg is null)
            {
                return;
            }

            try
            {
                await delg.Update();
            }
            catch (Exception ex)
            {
                Logger.Error("Error in delegate Update", ex);
            }
        }

        protected virtual async Task<bool> GetUrl(UrlType urlType)
        {
            if ((urlType == UrlType.Start && GotStartUrl) || string.IsNullOrWhiteSpace(LocalIPAddressString) || string.IsNullOrWhiteSpace(FQDN))
            {
                return false;
            }
            else if (urlType == UrlType.Stop)
            {
                GotStartUrl = false;
            }
            string url;
            switch (urlType)
            {
                case UrlType.Start: url = Config.GetUrlStart; break;
                case UrlType.Stop: url = Config.GetUrlStop; break;
                case UrlType.Update: url = Config.GetUrlUpdate; break;
                case UrlType.Config: url = Config.GetUrlConfig; break;
                default: return false;
            }

            if (!string.IsNullOrWhiteSpace(url))
            {
                url = ReplaceUrl(url);
                try
                {
                    KeyValuePair<string, object>[] headers = (Authorization is null ? null : new KeyValuePair<string, object>[] { new KeyValuePair<string, object>("Authorization", Authorization) });
                    byte[] bytes = await RequestMaker.MakeRequestAsync(new Uri(url), headers: headers);
                    if (urlType == UrlType.Start)
                    {
                        GotStartUrl = true;
                    }
                    else if (urlType == UrlType.Update)
                    {
                        // if the update url sends bytes, we assume a software update, and run the result as an .exe
                        if (bytes.Length != 0)
                        {
                            string tempFile = Path.Combine(OSUtility.TempFolder, "IPBanServiceUpdate.exe");
                            File.WriteAllBytes(tempFile, bytes);

                            // however you are doing the update, you must allow -c and -d parameters
                            // pass -c to tell the update executable to delete itself when done
                            // pass -d for a directory which tells the .exe where this service lives
                            string args = "-c \"-d=" + AppContext.BaseDirectory + "\"";
                            Process.Start(tempFile, args);
                        }
                    }
                    else if (urlType == UrlType.Config && bytes.Length != 0)
                    {
                        await WriteConfigAsync(Encoding.UTF8.GetString(bytes));
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Error getting url of type {0} at {1}", urlType, url);
                }
            }
            return true;
        }

        private async Task UpdateUpdaters()
        {
            // hit start url if first time, if not first time will be ignored
            if (!(await GetUrl(UrlType.Start)))
            {
                // send update
                await GetUrl(UrlType.Update);
            }

            List<IUpdater> updatersTemp;

            // lock only long enough to copy the updaters
            lock (updaters)
            {
                updatersTemp = new List<IUpdater>(updaters);
            }

            // loop through temp list so we don't lock for very long
            foreach (IUpdater updater in updatersTemp)
            {
                try
                {
                    await updater.Update(CancelToken);
                }
                catch (Exception ex)
                {
                    Logger.Error("Error in updater {0}: {1}", updater.GetType().FullName, ex);
                }
            }
        }

        private Task UpdateFirewall()
        {
            if (firewallNeedsBlockedIPAddressesUpdate)
            {
                firewallNeedsBlockedIPAddressesUpdate = false;
                List<IPBanFirewallIPAddressDelta> deltas = ipDB.EnumerateIPAddressesDeltaAndUpdateState(true, UtcNow, Config.ResetFailedLoginCountForUnbannedIPAddresses).Where(i => !i.Added || !IsWhitelisted(i.IPAddress)).ToList();
                Logger.Warn("Updating firewall with {0} entries...", deltas.Count);
                Logger.Info("Firewall entries updated: {0}", string.Join(',', deltas.Select(d => d.IPAddress)));
                if (MultiThreaded)
                {
                    RunFirewallTask((token) => Firewall.BlockIPAddressesDelta(null, deltas, null, token));
                }
                else
                {
                    Firewall.BlockIPAddressesDelta(null, deltas).Sync();
                }
            }

            return Task.CompletedTask;
        }

        private async Task CycleTimerElapsed()
        {
            if (IsRunning)
            {
                Logger.Trace("CycleTimerElapsed");

                // perform the cycle, will not throw out
                await RunCycle();

                // if we have no config at this point, use a 5 second cycle under the 
                // assumption that something threw an exception and will hopefully
                // succeed after a short break and another cycle
                int nextTimerMilliseconds = Math.Min(60000, Math.Max(1000,
                    (Config is null ? 5000 : (int)Config.CycleTime.TotalMilliseconds)));

                // configure the timer to run again
                cycleTimer.Change(nextTimerMilliseconds, Timeout.Infinite);
            }
        }

        private void ProcessIPAddressEvent(IPAddressLogEvent newEvent, List<IPAddressLogEvent> pendingEvents,
            TimeSpan minTimeBetweenEvents, string type)
        {
            if (newEvent.Type != IPAddressEventType.FailedLogin &&
                newEvent.Type != IPAddressEventType.SuccessfulLogin)
            {
                return;
            }

            newEvent.Source = (newEvent.Source ?? "?");
            newEvent.UserName = (newEvent.UserName ?? string.Empty);

            lock (pendingEvents)
            {
                IPAddressLogEvent existing = pendingEvents.FirstOrDefault(p => p.IPAddress == newEvent.IPAddress && (p.UserName is null || p.UserName == newEvent.UserName));
                if (existing is null)
                {
                    pendingEvents.Add(newEvent);
                }
                else
                {
                    existing.UserName = (existing.UserName ?? newEvent.UserName);

                    // if more than n seconds has passed, increment the counter
                    // we don't want to count multiple events that all map to the same ip address that happen rapidly
                    // multiple logs or event viewer entries can trigger quickly, piling up the counter too fast,
                    // locking out even a single failed login for example
                    if ((UtcNow - existing.Timestamp) >= minTimeBetweenEvents)
                    {
                        // update to the latest timestamp of the event
                        existing.Timestamp = UtcNow;

                        // increment counter
                        existing.Count += newEvent.Count;
                    }
                    else
                    {
                        Logger.Debug("Ignoring event {0} from {1}, min time between events has not elapsed", type, existing.IPAddress);
                    }
                }
            }
        }

        /// <summary>
        /// Process all pending failed logins
        /// </summary>
        private async Task ProcessPendingFailedLogins()
        {
            // make a quick copy of pending ip addresses so we don't lock it for very long
            List<IPAddressLogEvent> ipAddresses = null;
            lock (pendingFailedLogins)
            {
                if (pendingFailedLogins.Count != 0)
                {
                    // get a copy of success logins, we don't want to do a failed login if there was a successful login
                    // from the same ip address...
                    // TODO: one user reported getting both failed and success RDP logins, until the cause of this problem
                    // is tracked down, this will prevent that scenario
                    List<IPAddressLogEvent> successes;
                    lock (pendingSuccessfulLogins)
                    {
                        successes = new List<IPAddressLogEvent>(pendingSuccessfulLogins);
                    }
                    ipAddresses = new List<IPAddressLogEvent>(pendingFailedLogins.Where(f => !successes.Any(s => s.IPAddress.Equals(f.IPAddress))));
                    pendingFailedLogins.Clear();
                    Logger.Debug("{0} pending failed logins", pendingFailedLogins.Count);
                }
            }
            if (ipAddresses != null)
            {
                await ProcessPendingFailedLogins(ipAddresses);
            }
        }

        /// <summary>
        /// Process all pending successful logins
        /// </summary>
        private async Task ProcessPendingSuccessfulLogins()
        {
            // make a quick copy of pending ip addresses so we don't lock it for very long
            List<IPAddressLogEvent> ipAddresses = null;
            lock (pendingSuccessfulLogins)
            {
                if (pendingSuccessfulLogins.Count != 0)
                {
                    ipAddresses = new List<IPAddressLogEvent>(pendingSuccessfulLogins);
                    pendingSuccessfulLogins.Clear();
                }
            }
            if (ipAddresses != null)
            {
                await ProcessPendingSuccessfulLogins(ipAddresses);
            }
        }

        private Task ProcessPendingLogEvents()
        {
            // get copy of pending log events quickly in a lock and clear list
            List<IPAddressLogEvent> events = null;
            lock (pendingLogEvents)
            {
                events = new List<IPAddressLogEvent>(pendingLogEvents);
                pendingLogEvents.Clear();
            }

            List<IPAddressLogEvent> bannedIPs = new List<IPAddressLogEvent>();
            object transaction = BeginTransaction();
            try
            {
                // loop through events, for failed and successful logins, we want to group / aggregate the same event from the
                // same remote ip address
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
                            // if we are not already banned...
                            if (!DB.TryGetIPAddressState(evt.IPAddress, out IPBanDB.IPAddressState? state, transaction) ||
                                (state.Value != IPBanDB.IPAddressState.Active && state.Value != IPBanDB.IPAddressState.AddPending))
                            {
                                ProcessIPAddressEvent(evt, pendingFailedLogins, Config.MinimumTimeBetweenFailedLoginAttempts, "failed");
                            }
                            break;

                        case IPAddressEventType.SuccessfulLogin:
                            ProcessIPAddressEvent(evt, pendingSuccessfulLogins, Config.MinimumTimeBetweenSuccessfulLoginAttempts, "successful");
                            break;

                        case IPAddressEventType.Blocked:
                            // if we are not already banned...
                            if (!DB.TryGetIPAddressState(evt.IPAddress, out IPBanDB.IPAddressState? state2, transaction) ||
                                (state2.Value != IPBanDB.IPAddressState.Active && state2.Value != IPBanDB.IPAddressState.AddPending))
                            {
                                // make sure the ip address is ban pending
                                AddBannedIPAddress(evt.IPAddress, evt.Source, evt.UserName, bannedIPs,
                                evt.Timestamp, false, evt.Count, string.Empty, transaction, evt.External);
                            }
                            break;

                        case IPAddressEventType.Unblocked:
                            DB.SetIPAddressesState(new string[] { evt.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                            firewallNeedsBlockedIPAddressesUpdate = true;
                            break;
                    }
                }
                CommitTransaction(transaction);
            }
            catch (Exception ex)
            {
                RollbackTransaction(transaction);
                Logger.Error(ex);
            }
            ExecuteExternalProcessForBannedIPAddresses(bannedIPs);
            return Task.CompletedTask;
        }

        private void SetupWindowsEventViewer()
        {
            if (EventViewer is null &&
                UseWindowsEventViewer &&
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // attach Windows event viewer to the service
                EventViewer = new IPBanWindowsEventViewer(this);
            }
        }

        private void ParseAndAddUriFirewallRules(IPBanConfig newConfig)
        {
            List<IPBanUriFirewallRule> toRemove = new List<IPBanUriFirewallRule>(updaters.Where(u => u is IPBanUriFirewallRule).Select(u => u as IPBanUriFirewallRule));
            using StringReader reader = new StringReader(newConfig.FirewallUriRules);
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                line = line.Trim();
                string[] pieces = line.Split(',');
                if (pieces.Length == 3)
                {
                    if (TimeSpan.TryParse(pieces[1], out TimeSpan interval))
                    {
                        if (Uri.TryCreate(pieces[2], UriKind.Absolute, out Uri uri))
                        {
                            string rulePrefix = pieces[0];
                            IPBanUriFirewallRule newRule = new IPBanUriFirewallRule(Firewall, this, RequestMaker, rulePrefix, interval, uri);
                            if (updaters.Where(u => u.Equals(newRule)).FirstOrDefault() is IPBanUriFirewallRule existingRule)
                            {
                                // exact duplicate rule, do nothing
                                toRemove.Remove(existingRule);
                            }
                            else
                            {
                                // new rule, add it
                                updaters.Add(newRule);
                            }
                        }
                        else
                        {
                            Logger.Warn("Invalid uri format in uri firewall rule {0}", line);
                        }
                    }
                    else
                    {
                        Logger.Warn("Invalid timestamp format in uri firewall rule {0}", line);
                    }
                }
            }

            // remove any left-over rules that were not in the new config
            foreach (IPBanUriFirewallRule updater in toRemove)
            {
                updater.DeleteRule();
            }
        }

        private static int ExtractRepeatCount(Match match, string text)
        {
            // if the match is optional/empty just return 1
            if (match.Length == 0)
            {
                return 1;
            }

            // look for the first instance of a message repeated text for this match, up to the last newline
            int repeatStart = match.Index;
            int repeatEnd = match.Index + match.Length;
            while (repeatStart > 0)
            {
                if (text[repeatStart] == '\n')
                {
                    repeatStart++;
                    break;
                }
                repeatStart--;
            }
            while (repeatEnd < text.Length)
            {
                if (text[repeatEnd] == '\n')
                {
                    break;
                }
                repeatEnd++;
            }
            Match repeater = Regex.Match(text[repeatStart..repeatEnd],
                "message repeated (?<count>[0-9]+) times", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (repeater.Success)
            {
                return int.Parse(repeater.Groups["count"].Value, CultureInfo.InvariantCulture);
            }
            return 1;
        }
    }
}
