using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace IPBan
{
    /// <summary>
    /// IPBan integration for external applications
    /// </summary>
    public static class IPBanPlugin
    {
        private static readonly EventLog eventLog;

        /// <summary>
        /// Optional error handler
        /// </summary>
        public static Action<Exception> ErrorHandler { get; set; }

        /// <summary>
        /// Static constructor
        /// </summary>
        static IPBanPlugin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                 eventLog = new EventLog("Application", Environment.MachineName, "IPBanCustom");
            }
        }
      
        /// <summary>
        /// Log a failed login attempt to IPBan
        /// </summary>
        /// <param name="source">Source, i.e. RDP, SMTP, FTP, etc.</param>
        /// <param name="userName">User name if known</param>
        /// <param name="remoteIpAddress">The remote ip address that failed to login</param>
        public static void IPBanLoginFailed(string source, string userName, string remoteIpAddress)
        {
            try
            {
                // Windows
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string data = $"ipban failed login ip address: {remoteIpAddress}, source: {source}, user: {userName}";
                    eventLog.WriteEntry(data, EventLogEntryType.Warning);
                }
                // MAC
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    // not yet supporte
                }
                // Linux
                else if (Directory.Exists(@"/var/log"))
                {
                    File.AppendAllText("/var/log/ipbancustom_maildemon.log", $"{DateTime.UtcNow.ToString("u")}, ipban failed login, ip address: {remoteIpAddress}, source: {source}, user: {userName}");

                }
            }
            catch (Exception ex)
            {
                ErrorHandler?.Invoke(ex);
            }
        }
    }
}
