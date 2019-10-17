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
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBan
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
        /// Process name
        /// </summary>
        public static string ProcessName { get; }

        /// <summary>
        /// Static constructor
        /// </summary>
        static IPBanPlugin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                eventLog = new EventLog("Application", Environment.MachineName, "IPBanCustom");
            }
            using (Process p = Process.GetCurrentProcess())
            {
                ProcessName = p.ProcessName;
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
                    string data = $"ipban failed login, ip address: {remoteIpAddress}, source: {source}, user: {userName}";
                    eventLog.WriteEntry(data, EventLogEntryType.Warning);
                }
                // MAC
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    // not yet supported
                }
                // Linux
                else if (Directory.Exists(@"/var/log"))
                {
                    File.AppendAllText($"/var/log/ipbancustom_{ProcessName}.log", $"{DateTime.UtcNow.ToString("u")}, ipban failed login, ip address: {remoteIpAddress}, source: {source}, user: {userName}\n");
                }
            }
            catch (Exception ex)
            {
                ErrorHandler?.Invoke(ex);
            }
        }

        /// <summary>
        /// Log a successful login attempt to IPBan
        /// </summary>
        /// <param name="source">Source, i.e. RDP, SMTP, FTP, etc.</param>
        /// <param name="userName">User name if known</param>
        /// <param name="remoteIpAddress">The remote ip address that succeeded to login</param>
        public static void IPBanLoginSucceeded(string source, string userName, string remoteIpAddress)
        {
            try
            {
                // Windows
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string data = $"ipban success login, ip address: {remoteIpAddress}, source: {source}, user: {userName}";
                    eventLog.WriteEntry(data, EventLogEntryType.Warning);
                }
                // MAC
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    // not yet supported
                }
                // Linux
                else if (Directory.Exists(@"/var/log"))
                {
                    string processName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                    File.AppendAllText($"/var/log/ipbancustom_{ProcessName}.log", $"{DateTime.UtcNow.ToString("u")}, ipban success login, ip address: {remoteIpAddress}, source: {source}, user: {userName}\n");
                }
            }
            catch (Exception ex)
            {
                ErrorHandler?.Invoke(ex);
            }
        }
    }
}
