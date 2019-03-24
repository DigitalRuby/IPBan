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

namespace IPBan
{
    /// <summary>
    /// Failed login interface
    /// </summary>
    public interface IFailedLogin
    {
        /// <summary>
        /// Add a failed login
        /// </summary>
        /// <param name="info">IP address log info</param>
        void AddFailedLogin(IPAddressLogInfo info);
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
        void UnblockIPAddresses(IEnumerable<string> ipAddresses);
    }

    /// <summary>
    /// IPBan service interface
    /// </summary>
    public interface IIPBanService : IFailedLogin, IUnblockIPAddresses, IDisposable
    {
        /// <summary>
        /// Manually run regular processing - useful if testing
        /// </summary>
        void RunCycle();

        /// <summary>
        /// Update config file with new xml
        /// </summary>
        /// <param name="xml">New config file xml</param>
        void UpdateConfig(string xml);

        /// <summary>
        /// Manually process all pending ip addresses immediately
        /// </summary>
        void ProcessPendingFailedLogins();

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
        ILocalMachineExternalIPAddressLookup ExternalIPAddressLookup { get; }

        /// <summary>
        /// Extra handle for banned ip addresses
        /// </summary>
        IBannedIPAddressHandler BannedIPAddressHandler { get; }

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
        /// Update
        /// </summary>
        /// <returns>True if changes were made, false otherwise</returns>
        bool Update();

        /// <summary>
        /// Notify when an ip is banned
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <param name="userName">User name</param>
        /// <param name="banned">True if banned, false if unbanned</param>
        /// <returns>Task</returns>
        Task IPAddressBanned(string ip, string userName, bool banned);

        /// <summary>
        /// Notify when a login attempt fails
        /// </summary>
        /// <param name="ip">Origin IP Address of the login attempt</param>
        /// <param name="source">The source of the failed login</param>
        /// <param name="userName">User name</param>
        /// <returns>Task of bool. True if the ip sould be immediately banned, false otherwise</returns>
        Task<LoginFailedResult> LoginAttemptFailed(string ip, string source, string userName);

        /// <summary>
        /// Notify when a login attempt succeeds
        /// </summary>
        /// <param name="ip">Origin IP Address of the login attempt</param>
        /// <param name="source">The source of the failed login</param>
        /// <param name="userName">User name</param>
        /// <returns>Task</returns>
        Task LoginAttemptSucceeded(string ip, string source, string userName);

        /// <summary>
        /// Enumerate external blacklist
        /// </summary>
        /// <returns>Blacklist</returns>
        IEnumerable<string> EnumerateBlackList();

        /// <summary>
        /// Enumerate external whitelist
        /// </summary>
        /// <returns>Whitelist</returns>
        IEnumerable<string> EnumerateWhiteList();

        /// <summary>
        /// Check if an ip address is whitelisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        bool IsIPAddressWhitelisted(string ipAddress);

        /// <summary>
        /// Check if an ip address is blacklisted
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <returns>True if blacklisted, false otherwise</returns>
        bool IsIPAddressBlacklisted(string ipAddress);
    }

    /// <summary>
    /// Login failure result
    /// </summary>
    [Flags]
    public enum LoginFailedResult
    {
        /// <summary>
        /// Not whitelisted or blacklisted, use default behavior
        /// </summary>
        None = 0,

        /// <summary>
        /// The ip address is whitelisted
        /// </summary>
        Whitelisted = 1,

        /// <summary>
        /// The ip address is blacklisted
        /// </summary>
        Blacklisted = 2
    }
}
