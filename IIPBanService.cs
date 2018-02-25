using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPBan
{
    public interface IIPBanService : IDisposable
    {
        /// <summary>
        /// Ban/unban an ip address
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <param name="ban">True to ban, false to unban</param>
        void BanIpAddress(string ip, bool ban);

        /// <summary>
        /// Update config file with new xml
        /// </summary>
        /// <param name="xml">New config file xml</param>
        void UpdateConfig(string xml);
    }

    /// <summary>
    /// External configuration interface
    /// </summary>
    public interface IIPBanExternalConfig
    {
        /// <summary>
        /// Check if an ip is whitelisted
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        bool IsWhitelisted(string ip);

        /// <summary>
        /// Check if an ip is blacklisted
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <returns>True if blacklisted, false otherwise</returns>
        bool IsBlacklisted(string ip);
    }

    /// <summary>
    /// Interface for external communication of ip address ban, unband, config, etc.
    /// </summary>
    public interface IIPBanDelegate : IIPBanExternalConfig, IDisposable
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
        /// <param name="banned">True if banned, false if unbanned</param>
        void IPAddressBanned(string ip, bool banned);

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
}
