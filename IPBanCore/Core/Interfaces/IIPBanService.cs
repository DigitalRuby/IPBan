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

using System;
using System.Collections.Generic;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// IP address event interface
    /// </summary>
    public interface IIPAddressEventHandler
    {
        /// <summary>
        /// Add ip address events
        /// </summary>
        /// <param name="events">IP address events</param>
        void AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events);
    }

    /// <summary>
    /// Allow reading and writing of configuration
    /// </summary>
    public interface IConfigReaderWriter
    {
        /// <summary>
        /// Update config file with new xml
        /// </summary>
        /// <param name="xml">New config file xml</param>
        /// <returns>Task</returns>
        Task WriteConfigAsync(string xml);

        /// <summary>
        /// Read configuration
        /// </summary>
        /// <returns>Task with xml config</returns>
        Task<string> ReadConfigAsync();
    }

    /// <summary>
    /// IPBan service interface
    /// </summary>
    public interface IIPBanService : IIPAddressEventHandler, IConfigReaderWriter, IDisposable
    {
        /// <summary>
        /// Manually run regular processing - useful if testing
        /// </summary>
        /// <returns>Task</returns>
        Task RunCycleAsync();

        /// <summary>
        /// Replace place-holders in url with values from this service
        /// </summary>
        /// <param name="url">Url to replace</param>
        /// <returns>Replaced url</returns>
        string ReplaceUrl(string url);

        /// <summary>
        /// Add an updater for each cycle
        /// </summary>
        /// <param name="updater">Updater</param>
        /// <returns>True if added, false if null or already in the list</returns>
        bool AddUpdater(IUpdater updater);

        /// <summary>
        /// Attempt to get an updater of a specific type
        /// </summary>
        /// <typeparam name="T">Type</typeparam>
        /// <param name="result">Updater or default(T) if not found</param>
        /// <returns>True if found, false if not</returns>
        bool TryGetUpdater<T>(out T result);

        /// <summary>
        /// Remove an updater
        /// </summary>
        /// <param name="updater">Updater</param>
        /// <returns>True if removed, false otherwise</returns>
        bool RemoveUpdater(IUpdater updater);

        /// <summary>
        /// Run an action on the firewall queue
        /// </summary>
        /// <param name="action">Action to run on the firewall queue</param>
        /// <param name="name">Queue name, null for default</param>
        void RunFirewallTask(Func<CancellationToken, Task> action, string name = null);

        /// <summary>
        /// Whether the service is running
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Whether the cycle runs automatically
        /// </summary>
        bool ManualCycle { get; }

        /// <summary>
        /// Current configuration
        /// </summary>
        IPBanConfig Config { get; }

        /// <summary>
        /// Config changed event
        /// </summary>
        event Action<IPBanConfig> ConfigChanged;

        /// <summary>
        /// Whitelist
        /// </summary>
        IIPBanFilter Whitelist { get; }

        /// <summary>
        /// Blacklist
        /// </summary>
        IIPBanFilter Blacklist { get; }

        /// <summary>
        /// Local ip address string
        /// </summary>
        string LocalIPAddressString { get; }

        /// <summary>
        /// Remote ip address string
        /// </summary>
        string RemoteIPAddressString { get; }

        /// <summary>
        /// Fully qualified domain name
        /// </summary>
        string FQDN { get; }

        /// <summary>
        /// A unique id for this service
        /// </summary>
        string MachineGuid { get; }

        /// <summary>
        /// Http request maker
        /// </summary>
        IHttpRequestMaker RequestMaker { get; }

        /// <summary>
        /// Firewall
        /// </summary>
        IIPBanFirewall Firewall { get; }

        /// <summary>
        /// Dns lookup
        /// </summary>
        IDnsLookup DnsLookup { get; }

        /// <summary>
        /// External ip address lookup
        /// </summary>
        ILocalMachineExternalIPAddressLookup ExternalIPAddressLookup { get; set; }

        /// <summary>
        /// Extra handler for banned ip addresses
        /// </summary>
        IBannedIPAddressHandler BannedIPAddressHandler { get; set; }

        /// <summary>
        /// Delegate for extra handling
        /// </summary>
        IIPBanDelegate IPBanDelegate { get; }

        /// <summary>
        /// Operating system name
        /// </summary>
        string OSName { get; }

        /// <summary>
        /// Operating system version
        /// </summary>
        string OSVersion { get; }

        /// <summary>
        /// Whether the service is multi-threaded
        /// </summary>
        bool MultiThreaded { get; }

        /// <summary>
        /// Authorization
        /// </summary>
        SecureString Authorization { get; }

        /// <summary>
        /// Firewall types
        /// </summary>
        HashSet<Type> FirewallTypes { get; }
    }

    /// <summary>
    /// Interface for external communication of ip address ban, unband, config, etc.
    /// </summary>
    public interface IIPBanDelegate : IDisposable
    {
        /// <summary>
        /// Start - call only once. Dispose to stop.
        /// </summary>
        /// <param name="service">The service this delegate is attached to</param>
        void Start(IIPBanService service) { }

        /// <summary>
        /// Update, do housekeeping, etc.
        /// </summary>
        Task Update() => Task.CompletedTask;

        /// <summary>
        /// Notify when an ip is banned
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <param name="source">Source</param>
        /// <param name="userName">User name</param>
        /// <param name="machineGuid">Machine guid</param>
        /// <param name="osName">OS name</param>
        /// <param name="osVersion">OS version</param>
        /// <param name="timestamp">Timestamp</param>
        /// <param name="banned">True if banned, false if unbanned</param>
        /// <returns>Task</returns>
        Task IPAddressBanned(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp, bool banned) => Task.CompletedTask;

        /// <summary>
        /// Notify when a login attempt fails
        /// </summary>
        /// <param name="ip">Origin IP Address of the login attempt</param>
        /// <param name="source">The source of the failed login</param>
        /// <param name="userName">User name</param>
        /// <param name="machineGuid">Machine guid</param>
        /// <param name="osName">OS name</param>
        /// <param name="osVersion">OS version</param>
        /// <param name="count">Number of failures</param>
        /// <param name="timestamp">Timestamp</param>
        /// <returns>Task</returns>
        Task LoginAttemptFailed(string ip, string source, string userName, string machineGuid, string osName, string osVersion, int count, DateTime timestamp) => Task.CompletedTask;

        /// <summary>
        /// Notify when a login attempt succeeds
        /// </summary>
        /// <param name="ip">Origin IP Address of the login attempt</param>
        /// <param name="source">The source of the failed login</param>
        /// <param name="userName">User name</param>
        /// <param name="machineGuid">Machine guid</param>
        /// <param name="osName">OS name</param>
        /// <param name="osVersion">OS version</param>
        /// <param name="count">Number of successes</param>
        /// <param name="timestamp">Timestamp</param>
        /// <returns>Task</returns>
        Task LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid, string osName, string osVersion, int count, DateTime timestamp) => Task.CompletedTask;
    }
}
