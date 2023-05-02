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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Base ipban service class. Configuration, firewall and many other properties will
    /// not be initialized until the first RunCycle is called.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public partial class IPBanService : IIPBanService, IIsWhitelisted
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public IPBanService()
        {
            OSName = OSUtility.Name + (string.IsNullOrWhiteSpace(OSUtility.FriendlyName) ? string.Empty : " (" + OSUtility.FriendlyName + ")");
            OSVersion = OSUtility.Version;

            // by default, all IPBan services will parse log files
            updaters.Add(new IPBanLogFileManager(this));

            var version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? string.Empty;
            var appName = Assembly.GetEntryAssembly()?.GetName().Name ?? string.Empty;
            appName = (appName.Contains("ipbanpro", StringComparison.OrdinalIgnoreCase) ? "ipbanpro" : "ipban");
            AppName = appName + " " + version;
            cycleActions = new (string, Func<Task>)[]
            {
                ("GC", () => { GC.GetTotalMemory(true); return Task.CompletedTask; }),
                (nameof(UpdateConfiguration), UpdateConfiguration),
                (nameof(SetNetworkInfo), SetNetworkInfo),
                (nameof(UpdateDelegate), UpdateDelegate),
                (nameof(UpdateUpdaters), UpdateUpdaters),
                (nameof(UpdateExpiredIPAddressStates), UpdateExpiredIPAddressStates),
                (nameof(ProcessPendingLogEvents), ProcessPendingLogEvents),
                (nameof(ProcessPendingFailedLogins), ProcessPendingFailedLogins),
                (nameof(ProcessPendingSuccessfulLogins), ProcessPendingSuccessfulLogins),
                (nameof(UpdateFirewall), UpdateFirewall),
                (nameof(RunFirewallTasks), RunFirewallTasks),
                (nameof(OnUpdate), OnUpdate),
                (nameof(ShowRunningMessage), ShowRunningMessage)
            };
        }

        /// <summary>
        /// Create an IPBanService by searching all types in all assemblies
        /// </summary>
        /// <returns>IPBanService (if not found an exception is thrown)</returns>
        public static T CreateService<T>() where T : IPBanService
        {
            return Activator.CreateInstance(typeof(T), BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance, null, null, null) as T;
        }

        /// <summary>
        /// Manually run one cycle. This is called automatically, unless ManualCycle is true.
        /// </summary>
        public async Task RunCycleAsync()
        {
            try
            {
                // ensure we don't stack multiple cycles
                if (await cycleLock.WaitAsync(1))
                {
                    try
                    {
                        if (IsRunning)
                        {
                            foreach (var action in cycleActions)
                            {
                                try
                                {
                                    await action.action();
                                }
                                catch (Exception ex)
                                {
                                    Logger.Error(ex, "Error in cycle action {0}", action.name);
                                }
                            }
                        }
                    }
                    finally
                    {
                        cycleLock.Release();
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException)
                {
                    Logger.Error($"Error on {nameof(IPBanService)}.{nameof(RunCycleAsync)}", ex);
                }
            }
        }

        /// <summary>
        /// Add an ip address log event
        /// </summary>
        /// <param name="events">IP address events</param>
        public void AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events)
        {
            var eventsArray = events.ToArray();
            lock (pendingLogEvents)
            {
                pendingLogEvents.AddRange(eventsArray);
            }
        }

        /// <summary>
        /// Write a new config file
        /// </summary>
        /// <param name="xml">Xml of the new config file</param>
        /// <returns>Task</returns>
        public async Task WriteConfigAsync(string xml)
        {
            // Ensure valid xml before writing the file
            XmlDocument doc = new();
            using (XmlReader xmlReader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            {
                CheckCharacters = false,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                IgnoreWhitespace = true
            }))
            {
                doc.Load(xmlReader);
            }
            await ConfigReaderWriter.WriteConfigAsync(xml);
        }

        /// <summary>
        /// Read configuration
        /// </summary>
        /// <returns>Configuration xml</returns>
        public Task<string> ReadConfigAsync()
        {
            return ConfigReaderWriter.ReadConfigAsync();
        }

        /// <summary>
        /// Read override configuration
        /// </summary>
        /// <returns>Configuration override xml</returns>
        public Task<string> ReadOverrideConfigAsync()
        {
            return ConfigOverrideReaderWriter.ReadConfigAsync();
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

            try
            {
                GC.SuppressFinalize(this);
                cycleLock.WaitAsync().Sync();
                IsRunning = false;
                GetUrl(UrlType.Stop).Sync();
                cycleTimer?.Dispose();
                IPBanDelegate?.Dispose();
                IPBanDelegate = null;
                lock (updaters)
                {
                    foreach (IUpdater updater in updaters.ToArray())
                    {
                        updater.Dispose();
                    }
                    updaters.Clear();
                }
                ipDB?.Dispose();
                Logger.Warn("Stopped IPBan service");
            }
            finally
            {
                stopEvent.Release();
            }
        }

        /// <summary>
        /// Initialize and start the service
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        public async Task RunAsync(CancellationToken cancelToken)
        {
            CancelToken = cancelToken;

            if (!IsRunning)
            {
                try
                {
                    IsRunning = true;

                    // set version
                    AssemblyVersion = IPBanService.IPBanAssembly.GetName().Version.ToString();

                    // create db
                    ipDB = new IPBanDB(DatabasePath ?? "ipban.sqlite");

                    // add some services
                    AddUpdater(new IPBanUnblockIPAddressesUpdater(this, Path.Combine(AppContext.BaseDirectory, "unban*.txt")));
                    AddUpdater(new IPBanBlockIPAddressesUpdater(this, Path.Combine(AppContext.BaseDirectory, "ban*.txt")));
                    AddUpdater(DnsList);
                    AddUpdater(IPThreatUploader ??= new IPBanIPThreatUploader(this));

                    // start delegate if we have one
                    var delg = IPBanDelegate;
                    if (delg is not null)
                    {
                        Logger.Debug("Starting service delegate");
                        delg.Start(this);
                    }

                    Logger.Warn("IPBan service started and initialized");
                    Logger.WriteLogLevels();

                    // setup cycle timer if needed
                    if (!ManualCycle)
                    {
                        // create a new timer that goes off in 1 second, this will change as the config is
                        // loaded and the cycle time becomes whatever is in the config
                        cycleTimer = new Timer(async (_state) =>
                        {
                            try
                            {
                                await CycleTimerElapsed();
                            }
                            catch
                            {
                            }
                        }, null, 1000, Timeout.Infinite);
                    }

                    if (!ManualCycle)
                    {
                        await Task.Delay(Timeout.Infinite, cancelToken);
                    }
                }
                catch (Exception ex)
                {
                    if (ex is not OperationCanceledException)
                    {
                        Logger.Error($"Error in {nameof(IPBanService)}.{nameof(IPBanService.RunAsync)}", ex);
                    }
                }
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
        /// Wait for service to stop
        /// </summary>
        /// <param name="timeoutMilliseconds">Timeout in milliseconds</param>
        /// <returns>True if service stopped, false otherwise</returns>
        public Task<bool> WaitAsync(int timeoutMilliseconds)
        {
            return stopEvent.WaitAsync(timeoutMilliseconds);
        }

        /// <summary>
        /// Replace place-holders in url with values from this service
        /// </summary>
        /// <param name="url">Url to replace</param>
        /// <returns>Replaced url</returns>
        public string ReplaceUrl(string url)
        {
            return url.Replace("###IPADDRESS###", LocalIPAddressString.UrlEncode())
                .Replace("###REMOTEIPADDRESS###", RemoteIPAddressString.UrlEncode())
                .Replace("###MACHINENAME###", OSUtility.FQDN.UrlEncode())
                .Replace("###VERSION###", Version.UrlEncode())
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
        /// <param name="updater">Updater</param>
        /// <returns>True if removed, false otherwise</returns>
        public bool RemoveUpdater(IUpdater updater)
        {
            lock (updaters)
            {
                return updaters.Remove(updater);
            }
        }

        /// <summary>
        /// Run a task on the firewall queue
        /// </summary>
        /// <typeparam name="T">Type of state</typeparam>
        /// <param name="action">Action to run</param>
        /// <param name="state">State</param>
        public void RunFirewallTask<T>(Func<T, CancellationToken, Task> action, T state)
        {
            if (!IsRunning || CancelToken.IsCancellationRequested)
            {
                return;
            }
            else if (MultiThreaded)
            {
                lock (firewallTasks)
                {
                    firewallTasks.Add((action, state));
                }
            }
            else
            {
                action.Invoke(state, CancelToken).Sync();
            }
        }

        private class TestTimeSource : NLog.Time.TimeSource
        {
            public override DateTime Time => IPBanService.UtcNow;

            public override DateTime FromSystemTime(DateTime systemTime)
            {
                return systemTime.ToUniversalTime();
            }
        }

        /// <summary>
        /// Create a test IPBanService
        /// </summary>
        /// <param name="directory">Root directory</param>
        /// <param name="configFileName">Config file name</param>
        /// <param name="defaultBannedIPAddressHandlerUrl">Url for banned ip handling or null to not handle banned ip</param>
        /// <param name="configFileModifier">Change config file (param are file text, returns new file text)</param>
        /// <param name="cleanup">Whether to cleanup files first before starting the service</param>
        /// <returns>Service</returns>
        public static T CreateAndStartIPBanTestService<T>(string directory = null, string configFileName = null, string defaultBannedIPAddressHandlerUrl = null,
            Func<string, string> configFileModifier = null, bool cleanup = true) where T : IPBanService
        {
            // if not running tests, do nothing
            if (!UnitTestDetector.Running)
            {
                return default;
            }

            NLog.Time.TimeSource.Current = new TestTimeSource();
            string defaultNLogConfig = $@"<?xml version=""1.0""?>
<nlog xmlns=""http://www.nlog-project.org/schemas/NLog.xsd"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" throwExceptions=""false"" internalLogToConsole=""false"" internalLogToConsoleError=""false"" internalLogLevel=""Trace"">
  <targets>
    <target name=""logfile"" xsi:type=""File"" fileName=""${{basedir}}/logfile.txt"" encoding=""UTF-8""/>
    <target name=""console"" xsi:type=""Console""/>
  </targets>
  <rules>
    <logger name=""*"" minlevel=""Debug"" writeTo=""logfile""/>
    <logger name=""*"" minlevel=""Debug"" writeTo=""console""/>
  </rules>
</nlog>";
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "nlog.config"), defaultNLogConfig);

            if (cleanup)
            {
                CleanupIPBanTestFiles();
            }

            DefaultHttpRequestMaker.DisableLiveRequests = true;
            if (string.IsNullOrWhiteSpace(directory))
            {
                directory = AppContext.BaseDirectory;
            }
            if (string.IsNullOrWhiteSpace(configFileName))
            {
                configFileName = IPBanConfig.DefaultFileName;
            }
            string configFilePath = Path.Combine(directory, configFileName);
            string configFileOverridePath = Path.Combine(directory, configFileName.Replace("ipban.config", "ipban.override.config")); ;
            string configFileText = File.ReadAllText(configFilePath);
            string configFileOverrideText = File.ReadAllText(configFileOverridePath);
            configFilePath += ".tmp";
            configFileOverridePath += ".tmp";
            if (configFileModifier != null)
            {
                configFileText = configFileModifier(configFileText);
            }
            ExtensionMethods.FileWriteAllTextWithRetry(configFilePath, configFileText);
            ExtensionMethods.FileWriteAllTextWithRetry(configFileOverridePath, configFileOverrideText);
            T service = IPBanService.CreateService<T>();
            service.ConfigFilePath = configFilePath;
            service.MultiThreaded = false;
            service.ManualCycle = true;
            service.DnsList = null; // too slow for tests, turn off
            if (defaultBannedIPAddressHandlerUrl is null)
            {
                service.BannedIPAddressHandler = NullBannedIPAddressHandler.Instance;
            }
            else
            {
                service.BannedIPAddressHandler = new DefaultBannedIPAddressHandler { BaseUrl = defaultBannedIPAddressHandlerUrl };
            }
            service.Version = "1.1.1.1";
            service.RunAsync(CancellationToken.None).Sync();
            service.RunCycleAsync().Sync();
            service.DB.Truncate(true);
            service.Firewall.Truncate();
            return service;
        }

        /// <summary>
        /// Cleanup test files
        /// </summary>
        public static void CleanupIPBanTestFiles()
        {
            // if not running tests, do nothing
            if (!UnitTestDetector.Running)
            {
                return;
            }

            DefaultHttpRequestMaker.DisableLiveRequests = true;
            string logFilePath = Path.Combine(AppContext.BaseDirectory, "logfile.txt");
            if (File.Exists(logFilePath))
            {
                File.Delete(logFilePath);
            }
            ExtensionMethods.RemoveDatabaseFiles();
        }

        /// <summary>
        /// Dispose of an IPBanService created with CreateAndStartIPBanTestService
        /// </summary>
        /// <param name="service">Service to dispose</param>
        public static void DisposeIPBanTestService(IPBanService service)
        {
            // if not running tests, do nothing
            if (!UnitTestDetector.Running)
            {
                return;
            }

            if (service != null)
            {
                if (File.Exists(Path.Combine(AppContext.BaseDirectory, "nlog.config")))
                {
                    File.Delete(Path.Combine(AppContext.BaseDirectory, "nlog.config"));
                }
                service.Firewall.Truncate();
                service.RunCycleAsync().Sync();
                service.IPBanDelegate = null;
                service.Dispose();
                ExtensionMethods.RemoveDatabaseFiles();
                NLog.Time.TimeSource.Current = new NLog.Time.AccurateUtcTimeSource();
                IPBanService.UtcNow = default;
            }
        }

        /// <inheritdoc />
        public bool IsWhitelisted(string entry) => Config.IsWhitelisted(entry);

        /// <inheritdoc />
        public bool IsWhitelisted(IPAddressRange range) => Config.IsWhitelisted(range);
    }
}
