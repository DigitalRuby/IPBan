using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IPBan
{
    /// <summary>
    /// Handler for ip addresses
    /// </summary>
    public interface IIPBanIPAddressHandler
    {
        /// <summary>
        /// Add an ip address and user name to be checked later
        /// </summary>
        /// <param name="ipAddress">IP Address, required</param>
        /// <param name="userName">User Name, optional</param>
        void AddPendingIPAddressAndUserName(string ipAddress, string userName = null);
    }

    public interface IIPBanService : IIPBanIPAddressHandler, IDisposable
    {
        /// <summary>
        /// Update config file with new xml
        /// </summary>
        /// <param name="xml">New config file xml</param>
        void UpdateConfig(string xml);

        /// <summary>
        /// Local ip address string
        /// </summary>
        string LocalIPAddressString { get; }

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
        /// Operating system name
        /// </summary>
        string OSName { get; }

        /// <summary>
        /// Operating system version
        /// </summary>
        string OSVersion { get; }
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
        /// <param name="userName">User name</param>
        /// <returns>Task of bool. True if the ip sould be immediately banned, false otherwise</returns>
        Task<LoginFailedResult> LoginAttemptFailed(string ip, string userName);

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
    }

    /// <summary>
    /// Login failure results
    /// </summary>
    [Flags]
    public enum LoginFailedResult
    {
        /// <summary>
        /// No result, use default behavior
        /// </summary>
        None = 0,

        /// <summary>
        /// The ip address country is whitelisted
        /// </summary>
        CountryIsWhitelisted = 1,

        /// <summary>
        /// The ip address country is blacklisted
        /// </summary>
        CountryIsBlacklisted = 2,

        /// <summary>
        /// The ip address country is not whitelisted and the whitelist has countries in it
        /// </summary>
        CountryIsNotWhitelisted = 4,

        /// <summary>
        /// Whitelisted bitmask
        /// </summary>
        Whitelisted = CountryIsWhitelisted,

        /// <summary>
        /// Blacklisted bitmask
        /// </summary>
        Blacklisted = CountryIsBlacklisted | CountryIsNotWhitelisted
    }
}
