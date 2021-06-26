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
using System.IO;
using System.Reflection;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    public partial class IPBanService
    {
        private static readonly char[] regexTrimChars = new[]
        {
            ',', ';', '|', '_', '-', '/', '\'', '\"', '(', ')', '[', ']', '{', '}', ' ', '\t', '\r', '\n'
        };

        private static readonly char[] userNamePrefixChars = new[] { ',', '\\' };

        // batch failed logins every cycle
        private readonly List<IPAddressLogEvent> pendingFailedLogins = new();
        private readonly List<IPAddressLogEvent> pendingSuccessfulLogins = new();
        private readonly List<IPAddressLogEvent> pendingLogEvents = new();
        private readonly HashSet<IUpdater> updaters = new();
        private readonly SemaphoreSlim stopEvent = new(0, 1);
        private readonly Dictionary<string, AsyncQueue<Func<CancellationToken, Task>>> firewallQueue = new();
        private readonly SemaphoreSlim cycleLock = new(1, 1);

        private System.Threading.Timer cycleTimer;
        private bool firewallNeedsBlockedIPAddressesUpdate;
        private IPBanDB ipDB;
        private bool whitelistChanged;
        private bool updateBannedIPAddressesOnStartCalled;

        /// <summary>
        /// Whether start url has been gotten
        /// </summary>
        protected bool GotStartUrl { get; set; }

        /// <summary>
        /// IPBan Assembly
        /// </summary>
        public static Assembly IPBanAssembly { get; } = typeof(IPBanService).Assembly;

        /// <summary>
        /// Config file path
        /// </summary>
        public string ConfigFilePath
        {
            get => ConfigReaderWriter.Path;
            set
            {
                ConfigReaderWriter.Path = value;
                ConfigOverrideReaderWriter.Path = value.Replace("ipban.config", "ipban.override.config");
            }
        }

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
        /// The dns server list implementation - defaults to IPBanDnsServerList
        /// </summary>
        public IDnsServerList DnsList { get; set; } = new IPBanDnsServerList();

        /// <summary>
        /// External ip address implementation - defaults to ExternalIPAddressLookupDefault.Instance
        /// </summary>
        public ILocalMachineExternalIPAddressLookup ExternalIPAddressLookup { get; set; } = LocalMachineExternalIPAddressLookupDefault.Instance;

        /// <summary>
        /// Extra handler for banned ip addresses (optional)
        /// </summary>
        public IBannedIPAddressHandler BannedIPAddressHandler { get; set; } = new DefaultBannedIPAddressHandler();

        /// <summary>
        /// Firewall creator
        /// </summary>
        public IFirewallCreator FirewallCreator { get; set; } = new DefaultFirewallCreator();

        /// <summary>
        /// Configuration
        /// </summary>
        public IPBanConfig Config { get; private set; }

        /// <summary>
        /// Whitelist
        /// </summary>
        public IIPBanFilter Whitelist => Config.WhitelistFilter;

        /// <summary>
        /// Blacklist
        /// </summary>
        public IIPBanFilter Blacklist => Config.BlacklistFilter;

        /// <summary>
        /// Config changed event
        /// </summary>
        public event Action<IPBanConfig> ConfigChanged;

        /// <summary>
        /// Config reader/writer
        /// </summary>
        public IPBanConfigReaderWriter ConfigReaderWriter { get; } = new IPBanConfigReaderWriter();

        /// <summary>
        /// Config override reader/writer
        /// </summary>
        public IPBanConfigReaderWriter ConfigOverrideReaderWriter { get; } = new IPBanConfigReaderWriter();

        /// <summary>
        /// Version of the software
        /// </summary>
        public string Version { get; set; } = Assembly.GetEntryAssembly().GetName().Version.ToString();

        /// <summary>
        /// Local ip address
        /// </summary>
        public string LocalIPAddressString { get; set; }

        /// <summary>
        /// Remote ip address
        /// </summary>
        public string RemoteIPAddressString { get; set; }

        /// <summary>
        /// Other ip addresses, comma separated
        /// </summary>
        public string OtherIPAddressesString { get; set; }

        /// <summary>
        /// Fully qualified domain name
        /// </summary>
        public string FQDN { get; set; }

        /// <summary>
        /// Machine guid, null/empty for none
        /// </summary>
        public string MachineGuid { get; set; }

        /// <summary>
        /// Override the sqlite database path, leave null for default
        /// </summary>
        public string DatabasePath { get; set; }

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

        /// <summary>
        /// Whether to link up to the Windows event viewer on Start
        /// </summary>
        public bool UseWindowsEventViewer { get; set; } = true;

        /// <summary>
        /// Cancel token
        /// </summary>
        public CancellationToken CancelToken { get; private set; }

        private static DateTime? utcNow;
        /// <summary>
        /// Allows changing the current date time to facilitate testing of behavior over elapsed times. Set to default(DateTime) to revert to DateTime.UtcNow.
        /// </summary>
        public static DateTime UtcNow
        {
            get => utcNow ?? DateTime.UtcNow;
            set => utcNow = (value == default ? null : (DateTime?)value);
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
        /// Authorization header for requests
        /// </summary>
        public SecureString Authorization { get; set; }

        /// <summary>
        /// File name to write ip addresses to (one per line) to block the ip addresses in the file. Can comma separate each line and the second line will be a source of the ban.
        /// </summary>
        public string BlockIPAddressesFileName { get; } = Path.Combine(AppContext.BaseDirectory, "ban.txt");

        /// <summary>
        /// File name to write ip addresses to (one per line) to unblock the ip addresses in the file
        /// </summary>
        public string UnblockIPAddressesFileName { get; } = Path.Combine(AppContext.BaseDirectory, "unban.txt");

        /// <summary>
        /// Pending log events
        /// </summary>
        public IReadOnlyCollection<IPAddressLogEvent> PendingLogEvents
        {
            get
            {
                lock (pendingLogEvents)
                {
                    return pendingLogEvents.ToArray();
                }
            }
        }
    }
}