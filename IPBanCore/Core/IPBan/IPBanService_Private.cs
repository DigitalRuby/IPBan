﻿/*
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
using System.Xml;

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

        internal async Task UpdateConfiguration(CancellationToken cancelToken)
        {
            try
            {
                ConfigFilePath = (!File.Exists(ConfigFilePath) ? Path.Combine(AppContext.BaseDirectory, IPBanConfig.DefaultFileName) : ConfigFilePath);
                var configChange = await ConfigReaderWriter.CheckForConfigChangeAsync();
                var configChangeOverride = await ConfigOverrideReaderWriter.CheckForConfigChangeAsync();
                var newConfigFound = !string.IsNullOrWhiteSpace(configChange);
                var newConfigOverrideFound = !string.IsNullOrWhiteSpace(configChangeOverride);
                if (newConfigFound || newConfigOverrideFound)
                {
                    // if we have override config but no base config change, force reload the base config
                    //  as it will potentially contain remenants of the previous override config
                    if (newConfigOverrideFound && !newConfigFound)
                    {
                        newConfigFound = true;
                        configChange = await ConfigReaderWriter.CheckForConfigChangeAsync(true);
                    }

                    // merge override xml
                    string baseXml = configChange ?? Config?.Xml ?? throw new IOException("Failed to read " + ConfigFilePath);
                    string overrideXml = configChangeOverride;
                    XmlDocument finalXml = IPBanConfig.MergeXml(baseXml, overrideXml);
                    IPBanConfig oldConfig = Config;
                    IPBanConfig newConfig = IPBanConfig.LoadFromXml(finalXml, DnsLookup, DnsList, RequestMaker);
                    bool configChanged = oldConfig is null || oldConfig.Xml != newConfig.Xml;

                    // log that we have a new config
                    if (configChanged)
                    {
                        Logger.Info("Config file changed");
                    }
                    else
                    {
                        Logger.Debug("Config file force reloaded");
                    }
                    Logger.Trace("New config: " + newConfig.Xml);

                    // invoke config change callback, if any
                    ConfigChanged?.Invoke(newConfig);

                    // track the whitelist changing, we will need to re-process all ip addresses if the whitelist changed
                    whitelistChanged = (Config is null || !Config.WhitelistFilter.Equals(newConfig.WhitelistFilter));

                    // set new config and re-load everything
                    Config = newConfig;

                    // load the firewall, detecting a change by referencing the old config
                    await LoadFirewall(oldConfig);

                    // process firewall changes from configuration
                    await HandleFirewallConfigChange();                    
                    ParseAndAddUriFirewallRules();
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
        }

        private object BeginTransaction()
        {
            return ipDB.BeginTransaction();
        }

        private static void CommitTransaction(object transaction)
        {
            SqliteDB.CommitTransaction(transaction);
        }

        private static void RollbackTransaction(object transaction)
        {
            // if already committed, nothing happens
            SqliteDB.RollbackTransaction(transaction);
        }

        private async Task SetNetworkInfo(CancellationToken cancelToken)
        {
            if (string.IsNullOrWhiteSpace(LocalIPAddressString))
            {
                try
                {
                    LocalIPAddressString = NetworkUtility.GetSortedIPAddresses(preferInternal: true).FirstOrDefault()?.ToString();
                    Logger.Info("Local ip address: {0}", LocalIPAddressString);
                }
                catch
                {
                    // sometimes this will fail, don't bring down the application
                }
            }

            if (string.IsNullOrWhiteSpace(OtherIPAddressesString))
            {
                try
                {
                    OtherIPAddressesString = string.Join(',', NetworkUtility.GetSortedIPAddresses().Select(i => i.ToString()));
                }
                catch
                {
                    // ignore
                }
            }

            if (string.IsNullOrWhiteSpace(RemoteIPAddressString))
            {
                try
                {
                    IPAddress ipAddress = NetworkUtility.GetSortedIPAddresses().FirstOrDefault();
                    if (ipAddress.IsInternal())
                    {
                        // try querying through a web service
                        var bytes = await RequestMaker.MakeRequestAsync(new Uri("https://api.ipban.com/myip"), cancelToken: cancelToken);
                        var ipString = Encoding.UTF8.GetString(bytes);
                        if (IPAddress.TryParse(ipString, out var ipObj))
                        {
                            RemoteIPAddressString = ipObj.ToString();
                        }
                    }
                    else
                    {
                        RemoteIPAddressString = ipAddress?.ToString();
                    }
                    Logger.Info("Remote ip address: {0}", RemoteIPAddressString);
                }
                catch
                {
                    // sometimes ip check url will fail, there is nothing that can be done, don't bother logging
                }
            }

            // request new config file
            await GetUrl(UrlType.Config, cancelToken);
        }

        private async Task ProcessPendingFailedLogins(IReadOnlyList<IPAddressLogEvent> ipAddresses, CancellationToken cancelToken)
        {
            List<IPAddressLogEvent> bannedIpAddresses = [];
            object transaction = BeginTransaction();
            try
            {
                foreach (IPAddressLogEvent failedLogin in ipAddresses)
                {
                    try
                    {
                        string ipAddress = failedLogin.IPAddress;

                        if (!IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj))
                        {
                            // bad ip, ignore
                            continue;
                        }
                        else if (!Config.ProcessInternalIPAddresses && ipAddressObj.IsInternal())
                        {
                            // internal ip failed logins should not be processed
                            Logger.Info("Ignoring failed login for internal ip address {0} because ProcessInternalIPAddresses is false", ipAddress);
                            continue;
                        }

                        // normalize for firewall
                        ipAddressObj = ipAddressObj.Clean();
                        ipAddress = ipAddressObj.ToString();
                        string userName = failedLogin.UserName;
                        string source = failedLogin.Source;
                        string logData = failedLogin.LogData ?? string.Empty;
                        if (IsWhitelisted(ipAddress))
                        {
                            Logger.Log(failedLogin.LogLevel, "Login failure, ignoring whitelisted ip address {0}, {1}, {2}", ipAddress, userName, source);

                            // if delegate is not null and not an external event, send the event to the delegate
                            if (IPBanDelegate != null && !failedLogin.External)
                            {
                                await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, 0, UtcNow, failedLogin.NotificationFlags);
                            }
                        }
                        else
                        {
                            int maxFailedLoginAttempts;
                            bool hasUserNameWhitelist = false;
                            bool userNameWhitelisted = Config.IsWhitelisted(userName) ||
                                Config.IsUserNameWithinMaximumEditDistanceOfUserNameWhitelist(userName, out hasUserNameWhitelist);
                            if (userNameWhitelisted)
                            {
                                maxFailedLoginAttempts = Config.FailedLoginAttemptsBeforeBanUserNameWhitelist;
                            }
                            else
                            {
                                // see if there is an override for max failed login attempts
                                maxFailedLoginAttempts = (failedLogin.FailedLoginThreshold > 0 ? failedLogin.FailedLoginThreshold : Config.FailedLoginAttemptsBeforeBan);
                            }

                            DateTime now = failedLogin.Timestamp;

                            // check for the target user name for additional blacklisting checks
                            bool ipBlacklisted = Config.BlacklistFilter.IsFiltered(ipAddress);
                            bool userBlacklisted = (!ipBlacklisted && Config.BlacklistFilter.IsFiltered(userName));
                            bool userFailsWhitelistRegex = (!userBlacklisted && Config.UserNameFailsUserNameWhitelistRegex(userName));
                            bool editDistanceBlacklisted = (!ipBlacklisted && !userBlacklisted && !userFailsWhitelistRegex &&
                                (hasUserNameWhitelist && !userNameWhitelisted));
                            bool configBlacklisted = ipBlacklisted || userBlacklisted || userFailsWhitelistRegex || editDistanceBlacklisted;

                            // if the event came in with a count of 0 that means it is an automatic ban
                            int incrementCount = (failedLogin.Count < 1 ? maxFailedLoginAttempts : failedLogin.Count);
                            int newCount = ipDB.IncrementFailedLoginCount(ipAddress, userName, source, UtcNow, incrementCount, transaction);

                            Logger.Log(failedLogin.LogLevel, now, "Login failure: {0}, {1}, {2}, {3}, {4}", ipAddress, userName, source, newCount, logData);

                            // if the ip address is black listed or the ip address has reached the maximum failed login attempts before ban, ban the ip address
                            if (configBlacklisted || newCount >= maxFailedLoginAttempts)
                            {
                                Logger.Info("IP blacklisted: {0}, user name blacklisted: {1}, fails user name white list regex: {2}, user name edit distance blacklisted: {3}",
                                    ipBlacklisted, userBlacklisted, userFailsWhitelistRegex, editDistanceBlacklisted);

                                if (ipDB.TryGetIPAddressState(ipAddress, out IPBanDB.IPAddressState? state, transaction) &&
                                    (state.Value == IPBanDB.IPAddressState.Active || state.Value == IPBanDB.IPAddressState.AddPending))
                                {
                                    Logger.Log(failedLogin.LogLevel, now, "IP {0}, {1}, {2} ban pending.", ipAddress, userName, source);
                                }
                                else
                                {
                                    Logger.Debug("Failed login count {0} >= ban count {1}{2}", newCount, maxFailedLoginAttempts, (configBlacklisted ? " config blacklisted" : string.Empty));

                                    // if delegate is not null and not an external event, send it on to the delegate
                                    if (IPBanDelegate != null && !failedLogin.External)
                                    {
                                        await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, incrementCount, UtcNow, failedLogin.NotificationFlags);
                                    }
                                    AddBannedIPAddress(ipAddress, source, userName, bannedIpAddresses, now,
                                        configBlacklisted, newCount, failedLogin.ExtraInfo, transaction,
                                        failedLogin.External, failedLogin.LogData, failedLogin.NotificationFlags);
                                }
                            }
                            else
                            {
                                Logger.Debug("Failed login count {0} <= ban count {1}", newCount, maxFailedLoginAttempts);
                                if (OSUtility.UserIsActive(userName))
                                {
                                    Logger.Warn("Login failed for known active user {0}", userName);
                                }

                                // if delegate is not null and not an external event, send the event to the delegate
                                if (IPBanDelegate != null && !failedLogin.External)
                                {
                                    await IPBanDelegate.LoginAttemptFailed(ipAddress, source, userName, MachineGuid, OSName, OSVersion, incrementCount, UtcNow, failedLogin.NotificationFlags);
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
                IPThreatUploader.AddIPAddressLogEvents(bannedIpAddresses);
                ExecuteExternalProcessForIPAddresses(Config.ProcessToRunOnBan, bannedIpAddresses);
            }
            catch (Exception ex)
            {
                RollbackTransaction(transaction);
                Logger.Error(ex);
            }
        }

        private Task ProcessPendingSuccessfulLogins(IEnumerable<IPAddressLogEvent> ipAddresses, CancellationToken cancelToken)
        {
            List<IPAddressLogEvent> finalList = [];
            foreach (IPAddressLogEvent info in ipAddresses)
            {
                // if we have a valid ip that is not internal, process the successful login
                if (System.Net.IPAddress.TryParse(info.IPAddress, out System.Net.IPAddress ipAddressObj) &&
                    (Config.ProcessInternalIPAddresses || !ipAddressObj.IsInternal()))
                {
                    finalList.Add(info);
                    string ipString = ipAddressObj.ToString();
                    Logger.Log(info.LogLevel, "Login succeeded, address: {0}, user name: {1}, source: {2}",
                        info.IPAddress, info.UserName, info.Source);
                    if (Config.ClearFailedLoginsOnSuccessfulLogin)
                    {
                        DB.DeleteIPAddress(ipString);
                        firewallNeedsBlockedIPAddressesUpdate = true;
                    }
                }
            }
            if (IPBanDelegate != null)
            {
                return Task.Run(() =>
                {
                    try
                    {
                        foreach (IPAddressLogEvent info in finalList)
                        {
                            // pass the success login on
                            IPBanDelegate.LoginAttemptSucceeded(info.IPAddress, info.Source, info.UserName, MachineGuid, OSName, OSVersion, info.Count, info.Timestamp, info.NotificationFlags);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex);
                    }
                }, cancelToken);
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

        private void AddBannedIPAddress(string ipAddress, string source, string userName,
            List<IPAddressLogEvent> bannedIpAddresses, DateTime startBanDate, bool configBlacklisted,
            int counter, string extraInfo, object transaction, bool external, string logData, IPAddressNotificationFlags notificationFlags)
        {
            if (!System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress ipAddressObj))
            {
                // bad ip, ignore
                return;
            }
            else if (!Config.ProcessInternalIPAddresses && ipAddressObj.IsInternal())
            {
                // internal ip bans should not be processed
                Logger.Info("Ignoring ban request for internal ip address {0} because ProcessInternalIPAddresses is false", ipAddress);
                return;
            }
            else if (IsWhitelisted(ipAddress))
            {
                // never ban whitelisted ip addresses
                Logger.Info("Ignoring ban request for whitelisted ip address {0}", ipAddress);
                return;
            }

            TimeSpan[] banTimes = Config.BanTimes;
            TimeSpan banTime = banTimes.First();
            DateTime banEndDate = startBanDate + banTime;
            notificationFlags = external ? IPAddressNotificationFlags.None : notificationFlags;

            // if we have an ip in the database, use the ban time to move to the next ban slot in the list of ban times
            // if ban times only has one entry, do not do this
            if (banTimes.Length > 1 &&
                ipDB.TryGetIPAddress(ipAddress, out IPBanDB.IPAddressEntry ipEntry, transaction) &&
                ipEntry.BanStartDate != null && ipEntry.BanEndDate != null)
            {
                Logger.Debug("Multiple ban times detected, detecting if ip {0} can move to next ban time slot.", ipAddress);

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
            bannedIpAddresses?.Add(new IPAddressLogEvent(ipAddress, userName, source, adjustedCount,
                IPAddressEventType.Blocked, logData: logData, notificationFlags: notificationFlags));
            if (ipDB.SetBanDates(ipAddress, startBanDate, banEndDate, UtcNow, transaction))
            {
                firewallNeedsBlockedIPAddressesUpdate = true;
            }

            Logger.Warn(startBanDate, "Banning ip address: {0}, user name: {1}, config blacklisted: {2}, count: {3}, extra info: {4}, duration: {5}",
                ipAddress, userName, configBlacklisted, counter, extraInfo, banTime);

            // if this is a delegate callback (counter of 0), exit out - we don't want to run handlers or processes for shared banned ip addresses
            if (counter <= 0)
            {
                return;
            }
            else if (BannedIPAddressHandler != null)
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
                    ExecuteTask(IPBanDelegate.IPAddressBanned(ipAddress, source, userName, MachineGuid,
                        OSName, OSVersion, UtcNow, true, notificationFlags));
                }
                catch (Exception ex)
                {
                    Logger.Info("Error calling ipban delegate with banned ip address: " + ex.ToString());
                }
            }
        }

        /// <summary>
        /// Execute unban process in background
        /// </summary>
        /// <param name="programToRun">Program to run</param>
        /// <param name="ipAddresses">IP addresses, should be a non-shared collection</param>
        private void ExecuteExternalProcessForIPAddresses(string programToRun,
            IReadOnlyCollection<IPAddressLogEvent> ipAddresses)
        {
            if (ipAddresses is null || ipAddresses.Count == 0 || string.IsNullOrWhiteSpace(programToRun))
            {
                return;
            }
            foreach (string process in programToRun.Split('\n'))
            {
                string[] pieces = process.Trim().Split('|', StringSplitOptions.TrimEntries);
                if (pieces.Length != 2)
                {
                    throw new ArgumentException("Invalid config option for process to run: " + programToRun +
                        " -- should be two strings, | delimited with program and arguments.");
                }

                RunTask(() =>
                {
                    string programFullPath = Path.GetFullPath(pieces[0]);
                    string programArgs = pieces[1];

                    foreach (var ipAddress in ipAddresses)
                    {
                        if (string.IsNullOrWhiteSpace(ipAddress?.IPAddress))
                        {
                            continue;
                        }

                        // log data cleanup
                        var logData = (ipAddress.LogData ?? string.Empty)
                            .Replace("\"", string.Empty)
                            .Replace("'", string.Empty)
                            .Replace("\\", "/")
                            .Replace("\n", " ")
                            .Replace("\r", " ")
                            .Replace("\t", " ")
                            .Trim();

                        string replacedArgs = programArgs.Replace("###IPADDRESS###", ipAddress.IPAddress)
                            .Replace("###SOURCE###", ipAddress.Source ?? string.Empty)
                            .Replace("###USERNAME###", ipAddress.UserName ?? string.Empty)
                            .Replace("###APP###", AppName)
                            .Replace("###COUNT###", ipAddress.Count.ToStringInvariant())
                            .Replace("###LOG###", logData);

                        try
                        {
                            ProcessStartInfo psi = new()
                            {
                                FileName = programFullPath,
                                WorkingDirectory = Path.GetDirectoryName(programFullPath),
                                Arguments = replacedArgs
                            };
                            using Process p = Process.Start(psi);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed to execute process {0} {1}", programFullPath, replacedArgs);
                        }
                    }
                });
            }
        }

        private async Task UpdateBannedIPAddressesOnStart()
        {
            if (updateBannedIPAddressesOnStartCalled)
            {
                return;
            }
            updateBannedIPAddressesOnStartCalled = true;

            if (Config.ClearBannedIPAddressesOnRestart)
            {
                Logger.Warn("Clearing all banned ip addresses on start because ClearBannedIPAddressesOnRestart is set");
                ExecuteExternalProcessForIPAddresses(Config.ProcessToRunOnUnban,
                    Firewall.EnumerateBannedIPAddresses()
                    .Select(i => new IPAddressLogEvent(i, string.Empty, string.Empty, 0, IPAddressEventType.Unblocked))
                    .ToArray());
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
                await Firewall.BlockIPAddresses(null, ipDB.EnumerateBannedIPAddresses());

                // set firewall update flag, if any deltas are lingering in the db (state = add pending or remove pending) they will get
                // processed on the next cycle
                firewallNeedsBlockedIPAddressesUpdate = true;

                // report on initial count
                int count = ipDB.GetIPAddressCount();
                Logger.Warn("{0} total ip addresses in the {1} database", count, IPBanDB.FileName);
            }
        }

        /// <summary>
        /// Load firewall
        /// </summary>
        /// <param name="oldConfig">Old config</param>
        /// <returns>Task</returns>
        protected virtual async Task LoadFirewall(IPBanConfig oldConfig)
        {
            IIPBanFirewall existing = Firewall;

            // set the new firewall
            var newFirewall = FirewallCreator.CreateFirewall(FirewallTypes, Config, existing);

            // if we changed firewall, handle the change
            if (existing != newFirewall)
            {
                // cleanup the old firewall if it exists
                if (existing is not null)
                {
                    OnFirewallDisposing();
                    existing.Dispose();
                }

                Firewall = newFirewall;
                OnFirewallCreated();
                Logger.Warn("Loaded firewall type {0}", Firewall.GetType());

                // if there was an old firewall, remove it from updaters and transfer ips to new firewall
                if (existing is not null)
                {
                    RemoveUpdater(existing);

                    // transfer banned ip to new firewall
                    await Firewall.BlockIPAddresses(null, ipDB.EnumerateBannedIPAddresses());
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
                List<string> deleteList = new(oldConfig.ExtraRules.Select(r => r.Name));

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
        }

        private async Task HandleFirewallConfigChange()
        {
            // ensure firewall is cleared out if needed - will only execute once
            await UpdateBannedIPAddressesOnStart();

            // ensure windows event viewer is setup if needed - will only execute once
            SetupWindowsEventViewer();

            // add/update global rules
            Logger.Debug("Updating global whitelist with {0} ip addresses", Config.WhitelistFilter.IPAddressRanges.Count);
            await Firewall.AllowIPAddresses("GlobalWhitelist", Config.WhitelistFilter.IPAddressRanges);
            Logger.Debug("Updating global blacklist with {0} ip addresses", Config.BlacklistFilter.IPAddressRanges.Count);
            await Firewall.BlockIPAddresses("GlobalBlacklist", Config.BlacklistFilter.IPAddressRanges);

            // add/update user specified rules
            foreach (IPBanFirewallRule rule in Config.ExtraRules)
            {
                if (rule.Block)
                {
                    await Firewall.BlockIPAddresses(rule.Name, rule.IPAddressRanges, rule.AllowPortRanges);
                }
                else
                {
                    await Firewall.AllowIPAddresses(rule.Name, rule.IPAddressRanges, rule.AllowPortRanges);
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
                if (Config.BlacklistFilter.IsFiltered(ipAddress.IPAddress))
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

                    // if more than one ban time, we have tiered ban times where the ban time increases 
                    if (banTimes.Length > 1)
                    {
                        // Skip first ban time as it was already used. This also ensures that the i - 1 below won't cause an error.
                        for (i = 1; i < banTimes.Length; i++)
                        {
                            if (span < banTimes[i])
                            {
                                // this is the next span to ban
                                Logger.Info("Ban duration {0} expired for ip {1}", banTimes[i - 1], ipAddress.IPAddress);
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
                        unbanList?.Add(ipAddress.IPAddress);
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

        private async Task UpdateExpiredIPAddressStates(CancellationToken cancelToken)
        {
            HashSet<string> unbannedIPAddresses = [];
            DateTime now = UtcNow;
            DateTime failLoginCutOff = (now - Config.ExpireTime);
            DateTime banCutOff = now;
            object transaction = DB.BeginTransaction();
            try
            {
                HandleWhitelistChanged(transaction, unbannedIPAddresses);
                HandleExpiredLoginsAndBans(failLoginCutOff, banCutOff, transaction, unbannedIPAddresses);
                ExecuteExternalProcessForIPAddresses(Config.ProcessToRunOnUnban, unbannedIPAddresses
                    .Select(i => new IPAddressLogEvent(i, null, null, 0, IPAddressEventType.Unblocked)).ToArray());

                // notify delegate of all unbanned ip addresses
                if (IPBanDelegate != null)
                {
                    foreach (string ip in unbannedIPAddresses)
                    {
                        await IPBanDelegate.IPAddressBanned(ip, null, null, MachineGuid, OSName, OSVersion, UtcNow, false,
                            IPAddressNotificationFlags.All);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
                SqliteDB.RollbackTransaction(transaction);
            }
            finally
            {
                SqliteDB.CommitTransaction(transaction);
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

        private async Task UpdateDelegate(CancellationToken cancelToken)
        {
            IIPBanDelegate delg = IPBanDelegate;
            if (delg is null)
            {
                Logger.Debug("No delegate to update");
                return;
            }

            try
            {
                await delg.RunCycleAsync(cancelToken);
            }
            catch (Exception ex)
            {
                Logger.Error("Error in delegate Update", ex);
            }
        }
        
        /// <summary>
        /// Fires when firewall is created. Firewall property.
        /// </summary>
        protected virtual void OnFirewallCreated() { }

        /// <summary>
        /// Fires when firewall is about to be disposed. Firewall property.
        /// </summary>
        protected virtual void OnFirewallDisposing() { }

        /// <summary>
        /// OnUpdate
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task</returns>
        protected virtual Task OnUpdate(CancellationToken cancelToken) => Task.CompletedTask;

        /// <summary>
        /// Get url from config
        /// </summary>
        /// <param name="urlType">Type of url</param>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task of whether url get succeeded</returns>
        protected virtual async Task<bool> GetUrl(UrlType urlType, CancellationToken cancelToken)
        {
            if ((urlType == UrlType.Start && GotStartUrl) ||
                string.IsNullOrWhiteSpace(LocalIPAddressString) ||
                string.IsNullOrWhiteSpace(OSUtility.FQDN))
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
                    KeyValuePair<string, object>[] headers = (Authorization is null ? null : new KeyValuePair<string, object>[] { new("Authorization", Authorization) });
                    byte[] bytes = await RequestMaker.MakeRequestAsync(new Uri(url), headers: headers, cancelToken: cancelToken);
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
                            ProcessUtility.CreateDetachedProcess(tempFile, args);
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

        private async Task UpdateUpdaters(CancellationToken cancelToken)
        {
            // hit start url if first time, if not first time will be ignored
            if (!(await GetUrl(UrlType.Start, cancelToken)))
            {
                // send update
                await GetUrl(UrlType.Update, cancelToken);
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
                    await updater.Update(cancelToken);
                }
                catch (Exception ex)
                {
                    Logger.Error("Error in updater {0}: {1}", updater.GetType().FullName, ex);
                }
            }
        }

        private async Task UpdateFirewall(CancellationToken cancelToken)
        {
            if (firewallNeedsBlockedIPAddressesUpdate)
            {
                firewallNeedsBlockedIPAddressesUpdate = false;
                List<IPBanFirewallIPAddressDelta> deltas = ipDB.EnumerateIPAddressesDeltaAndUpdateState(true, UtcNow, Config.ResetFailedLoginCountForUnbannedIPAddresses).Where(i => !i.Added || !IsWhitelisted(i.IPAddress)).ToList();
                Logger.Warn("Updating firewall with {0} entries...", deltas.Count);
                Logger.Info("Firewall entries updated: {0}", string.Join(',', deltas.Select(d => d.IPAddress)));
                await Firewall.BlockIPAddressesDelta(null, deltas, null, cancelToken);
            }
        }

        private Task ShowRunningMessage(CancellationToken cancelToken)
        {
            if (!startMessageShown)
            {
                startMessageShown = true;
                Logger.Warn("IPBan is running correctly. You can perform a failed ssh or rdp login and watch this log to verify functionality.");
            }
            return Task.CompletedTask;
        }

        private async Task RunFirewallTasks(CancellationToken cancelToken)
        {
            const int maxCount = 1000;
            int count = 0;
            while (firewallTasks.TryDequeue(out var firewallTask))
            {
                Stopwatch sw = Stopwatch.StartNew();
                try
                {
                    Logger.Debug("Running firewall task {0}", firewallTask.Name);
                    var result = firewallTask.TaskToRun.DynamicInvoke(firewallTask.State, firewallTask.CancelToken);
                    if (result is Task task)
                    {
                        await task;
                    }
                    else if (result is ValueTask valueTask)
                    {
                        await valueTask;
                    }
                }
                catch (Exception ex)
                {
                    if (ex is not OperationCanceledException)
                    {
                        Logger.Error(ex);
                    }
                }
                finally
                {
                    sw.Stop();
                    Logger.Debug("Ran firewall task {0} in {1:0.00}s", firewallTask.Name, sw.Elapsed.TotalSeconds);
                }
                if (++count == maxCount)
                {
                    // behind in task processing
                    Logger.Warn("Firewall task processing is running behind, this will cause memory to increase.");
                    break;
                }
            }

            // ensure firewall is updated
            try
            {
                await Firewall.Update(cancelToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error updating firewall {0}", Firewall.GetType());
            }
        }

        private async Task RunCycleInBackground(CancellationToken cancelToken)
        {
            DateTime lastCycleTimestamp = DateTime.MinValue;
            TimeSpan minSleep = TimeSpan.FromMilliseconds(1);
            TimeSpan defaultCycleTime = TimeSpan.FromSeconds(15.0);

            while (IsRunning && !cancelToken.IsCancellationRequested)
            {
                var now = IPBanService.UtcNow;
                var elapsed = now - lastCycleTimestamp;
                var cycleTime = Config?.CycleTime ?? defaultCycleTime;

                if (elapsed >= cycleTime)
                {
                    Logger.Trace("CycleTimerElapsed");
                    await RunCycleAsync(cancelToken);
                    lastCycleTimestamp = IPBanService.UtcNow;
                }
                else
                {
                    // compute time to sleep for next cycle
                    var toSleep = cycleTime - elapsed;
                    if (toSleep < minSleep)
                    {
                        toSleep = minSleep;
                    }
                    Logger.Trace("Sleeping for {0} ms for next cycle", toSleep.TotalMilliseconds);
                    await Task.Delay(toSleep, cancelToken);
                }
            }
        }

        private static void ProcessIPAddressEvent(IPAddressLogEvent newEvent, List<IPAddressLogEvent> pendingEvents,
            TimeSpan minTimeBetweenEvents, string type)
        {
            if (newEvent.Type != IPAddressEventType.FailedLogin &&
                newEvent.Type != IPAddressEventType.SuccessfulLogin)
            {
                return;
            }

            newEvent.Source ??= "?";
            newEvent.UserName ??= string.Empty;

            lock (pendingEvents)
            {
                IPAddressLogEvent existing = pendingEvents.FirstOrDefault(p => p.IPAddress == newEvent.IPAddress &&
                    (string.IsNullOrWhiteSpace(p.UserName) || p.UserName == newEvent.UserName));
                if (existing is null)
                {
                    pendingEvents.Add(newEvent);
                }
                else
                {
                    existing.UserName ??= newEvent.UserName;

                    if (existing.FailedLoginThreshold <= 0)
                    {
                        existing.FailedLoginThreshold = newEvent.FailedLoginThreshold;
                    }

                    // if more than n seconds has passed, increment the counter
                    // we don't want to count multiple events that all map to the same ip address that happen rapidly
                    // multiple logs or event viewer entries can trigger quickly, piling up the counter too fast,
                    // locking out even a single failed login for example
                    if (newEvent.Type == IPAddressEventType.SuccessfulLogin)
                    {
                        // for success logins increase time to log between events as some events (SSH) are reported multiple times
                        minTimeBetweenEvents = TimeSpan.FromSeconds(15.0);
                    }

                    var timeDifference = UtcNow - existing.Timestamp;
                    if (timeDifference >= minTimeBetweenEvents)
                    {
                        // update to the latest timestamp of the event
                        existing.Timestamp = UtcNow;

                        // increment counter
                        existing.Count += newEvent.Count;
                    }
                    else
                    {
                        Logger.Debug("Ignoring event {0} from ip {1}, time {2:0.00}s did not exceed min time {3:0.00}s between events",
                            type,
                            existing.IPAddress,
                            timeDifference.TotalSeconds,
                            minTimeBetweenEvents.TotalSeconds);
                    }
                }
            }
        }

        /// <summary>
        /// Process all pending failed logins
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        private async Task ProcessPendingFailedLogins(CancellationToken cancelToken)
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
                await ProcessPendingFailedLogins(ipAddresses, cancelToken);
            }
        }

        /// <summary>
        /// Process all pending successful logins
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        private async Task ProcessPendingSuccessfulLogins(CancellationToken cancelToken)
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
                await ProcessPendingSuccessfulLogins(ipAddresses, cancelToken);
            }
        }

        private Task ProcessPendingLogEvents(CancellationToken cancelToken)
        {
            // get copy of pending log events quickly in a lock and clear list
            List<IPAddressLogEvent> events = null;
            lock (pendingLogEvents)
            {
                events = new List<IPAddressLogEvent>(pendingLogEvents);
                pendingLogEvents.Clear();
            }

            List<IPAddressLogEvent> bannedIPs = [];
            List<IPAddressLogEvent> unbannedIPs = [];
            object transaction = BeginTransaction();
            try
            {
                // loop through events, for failed and successful logins, we want to group / aggregate the same event from the
                // same remote ip address
                foreach (IPAddressLogEvent evt in events)
                {
                    Logger.Trace("Processing log event {0}...", evt);

                    if (!evt.IPAddress.TryNormalizeIPAddress(out string normalizedIPAddress))
                    {
                        continue;
                    }

                    // remove domain prefix from username
                    if (evt.UserName != null)
                    {
                        evt.UserName = evt.UserName.Trim();
                        int pos = evt.UserName.IndexOfAny(userNamePrefixChars);
                        if (pos >= 0)
                        {
                            evt.UserName = evt.UserName[++pos..];
                        }
                    }

                    evt.IPAddress = normalizedIPAddress;
                    switch (evt.Type)
                    {
                        case IPAddressEventType.FailedLogin:
                            // if we are not already banned...
                            if (!DB.TryGetIPAddressState(evt.IPAddress, out IPBanDB.IPAddressState? state, transaction) ||
                                state.Value == IPBanDB.IPAddressState.FailedLogin)
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
                                state2.Value == IPBanDB.IPAddressState.FailedLogin)
                            {
                                // make sure the ip address is ban pending
                                AddBannedIPAddress(evt.IPAddress, evt.Source, evt.UserName, bannedIPs,
                                    evt.Timestamp, false, evt.Count, evt.ExtraInfo, transaction, evt.External, evt.LogData, evt.NotificationFlags);
                            }
                            break;

                        case IPAddressEventType.Unblocked:
                            DB.SetIPAddressesState(new string[] { evt.IPAddress }, IPBanDB.IPAddressState.RemovePending, transaction);
                            firewallNeedsBlockedIPAddressesUpdate = true;
                            unbannedIPs.Add(evt);
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
            ExecuteExternalProcessForIPAddresses(Config.ProcessToRunOnBan, bannedIPs);
            ExecuteExternalProcessForIPAddresses(Config.ProcessToRunOnUnban, unbannedIPs);
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

        private void ParseAndAddUriFirewallRules()
        {
            List<IPBanUriFirewallRule> toRemove = new(updaters.Where(u => u is IPBanUriFirewallRule).Select(u => u as IPBanUriFirewallRule));
            using StringReader reader = new(Config.FirewallUriRules);
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                line = line.Trim();
                string[] pieces = line.Split(',', StringSplitOptions.TrimEntries);
                if (pieces.Length >= 3)
                {
                    if (TimeSpan.TryParse(pieces[1], out TimeSpan interval))
                    {
                        if (Uri.TryCreate(pieces[2], UriKind.Absolute, out Uri uri))
                        {
                            string rulePrefix = pieces[0];
                            int maxCount = 10000;
                            if (pieces.Length > 3 && int.TryParse(pieces[3], out int _maxCount))
                            {
                                maxCount = _maxCount;
                            }
                            IPBanUriFirewallRule newRule = new(Firewall, this, RequestMaker, rulePrefix, interval, uri, maxCount);
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
                        Logger.Warn("Invalid timespan format in uri firewall rule {0}", line);
                    }
                }
            }

            // remove any left-over rules that were not in the new config
            foreach (IPBanUriFirewallRule updater in toRemove.ToArray())
            {
                updater.DeleteRule();
                RemoveUpdater(updater);
            }
        }
    }
}
