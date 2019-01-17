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
        /// Add an ip address to be checked for banning later
        /// </summary>
        /// <param name="ipAddress">IP Address</param>
        /// <param name="source">Source</param>
        /// <param name="userName">User Name</param>
        void AddFailedLogin(string ipAddress, string source, string userName);
    }

    /// <summary>
    /// IPBan service interface
    /// </summary>
    public interface IIPBanService : IFailedLogin, IDisposable
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
        /// Operating system name
        /// </summary>
        string OSName { get; }

        /// <summary>
        /// Operating system version
        /// </summary>
        string OSVersion { get; }

        /// <summary>
        /// Whether to submit ip addresses for global ban list
        /// </summary>
        bool SubmitIPAddresses { get; set; }
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
