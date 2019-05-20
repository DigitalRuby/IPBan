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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
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
        Task AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events);
    }

    /// <summary>
    /// Unban ip addresses interface
    /// </summary>
    public interface IUnblockIPAddresses
    {
        /// <summary>
        /// Unban ip addresses
        /// </summary>
        /// <param name="ipAddresses">IP addresses to unban</param>
        /// <returns>Task</returns>
        Task UnblockIPAddresses(IEnumerable<string> ipAddresses);
    }

    /// <summary>
    /// IPBan service interface
    /// </summary>
    public interface IIPBanService : IIPAddressEventHandler, IUnblockIPAddresses, IDisposable
    {
        /// <summary>
        /// Manually run regular processing - useful if testing
        /// </summary>
        /// <returns>Task</returns>
        Task RunCycle();

        /// <summary>
        /// Update config file with new xml
        /// </summary>
        /// <param name="xml">New config file xml</param>
        void UpdateConfig(string xml);

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
        /// Check if an ip is whitelisted
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        bool IsWhitelisted(string ip);

        /// <summary>
        /// Whether the service is running
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Current configuration
        /// </summary>
        IPBanConfig Config { get; }

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
        /// Serial task queue
        /// </summary>
        SerialTaskQueue TaskQueue { get; }

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
    }

    /// <summary>
    /// Interface for external communication of ip address ban, unband, config, etc.
    /// </summary>
    public interface IIPBanDelegate : IDisposable
    {
        /// <summary>
        /// Start
        /// </summary>
        /// <param name="service">The service this delegate is attached to</param>
        void Start(IIPBanService service);

        /// <summary>
        /// Stop
        /// </summary>
        void Stop();

        /// <summary>
        /// Update, do housekeeping, etc.
        /// </summary>
        void Update();

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
        Task IPAddressBanned(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp, bool banned);

        /// <summary>
        /// Notify when a login attempt fails
        /// </summary>
        /// <param name="ip">Origin IP Address of the login attempt</param>
        /// <param name="source">The source of the failed login</param>
        /// <param name="userName">User name</param>
        /// <param name="machineGuid">Machine guid</param>
        /// <param name="osName">OS name</param>
        /// <param name="osVersion">OS version</param>
        /// <param name="timestamp">Timestamp</param>
        /// <returns>Task</returns>
        Task LoginAttemptFailed(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp);

        /// <summary>
        /// Notify when a login attempt succeeds
        /// </summary>
        /// <param name="ip">Origin IP Address of the login attempt</param>
        /// <param name="source">The source of the failed login</param>
        /// <param name="userName">User name</param>
        /// <param name="machineGuid">Machine guid</param>
        /// <param name="osName">OS name</param>
        /// <param name="osVersion">OS version</param>
        /// <param name="timestamp">Timestamp</param>
        /// <returns>Task</returns>
        Task LoginAttemptSucceeded(string ip, string source, string userName, string machineGuid, string osName, string osVersion, DateTime timestamp);

        /// <summary>
        /// Check if an ip address is whitelisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        bool IsIPAddressWhitelisted(string ipAddress);

        /// <summary>
        /// Fires whenever the delegate whitelist changes
        /// </summary>
        event Action WhitelistChanged;
    }
}
