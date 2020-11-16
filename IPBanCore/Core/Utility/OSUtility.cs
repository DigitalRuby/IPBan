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

#pragma warning disable CA1416 // Validate platform compatibility

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Operating system utility methods
    /// </summary>
    public class OSUtility
    {
        /// <summary>
        /// Unknown operating system
        /// </summary>
        public const string Unknown = "Unknown";

        /// <summary>
        /// Windows
        /// </summary>
        public const string Windows = "Windows";

        /// <summary>
        /// Linux
        /// </summary>
        public const string Linux = "Linux";

        /// <summary>
        /// Macintosh / OS 10+
        /// </summary>
        public const string Mac = "Mac";

        /// <summary>
        /// Operating system name (i.e. Windows, Linux or OSX)
        /// </summary>
        public static string Name { get; private set; }

        /// <summary>
        /// Operating system cpu architecture (i.e. x86 or x64)
        /// </summary>
        public static string CpuArchitecture { get; private set; }

        /// <summary>
        /// Operating system version
        /// </summary>
        public static string Version { get; private set; }

        /// <summary>
        /// Operating system friendly/code name
        /// </summary>
        public static string FriendlyName { get; private set; }

        /// <summary>
        /// Operating system description
        /// </summary>
        public static string Description { get; private set; }

        private static readonly string tempFolder;

        private static bool isWindows;
        private static bool isLinux;
        private static bool isMac;

        private static string processVerb;

        static OSUtility()
        {
            try
            {
                tempFolder = Path.GetTempPath();
                if (string.IsNullOrWhiteSpace(tempFolder))
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        tempFolder = "c://temp";
                        processVerb = "runas";
                    }
                    else
                    {
                        tempFolder = "/tmp";
                    }
                }
                Directory.CreateDirectory(tempFolder);
                LoadOSInfo();
            }
            catch (Exception ex)
            {
                Logger.Error("Error in OSUtility static constructor", ex);
            }
        }

        private static string ExtractRegex(string input, string regex, string defaultValue)
        {
            Match m = Regex.Match(input, regex, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            if (m.Success)
            {
                return m.Groups["value"].Value.Trim('[', ']', '"', '\'', '(', ')', ' ', '\r', '\n', '\t');
            }
            return defaultValue;
        }

        private static void LoadOSInfo()
        {
            Logger.Warn("Detecting os version...");

            // start off with built in version info, this is not as detailed or nice as we like,
            //  so we try some other ways to get more detailed information
            CpuArchitecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
            Version = Environment.OSVersion.Version.ToString();
            Description = RuntimeInformation.OSDescription;

            // attempt to get detailed version info
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                LoadVersionFromLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                LoadVersionFromWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                // TODO: Implement better for MAC
                Name = FriendlyName = OSUtility.Mac;
                FriendlyName = "OSX";
                isMac = true;
            }
            else
            {
                Name = OSUtility.Unknown;
                FriendlyName = "Unknown";
            }

            Logger.Warn("OS version detected: {0}", OSString());
        }

        private static void LoadVersionFromLinux()
        {
            Name = FriendlyName = OSUtility.Linux;
            isLinux = true;
            string tempFile = GetTempFileName();
            using Process p = Process.Start("/bin/bash", "-c \"cat /etc/*release* > " + tempFile + "\"");
            p.WaitForExit();
            System.Threading.Tasks.Task.Delay(100); // wait a small bit for file to really be closed
            string versionText = File.ReadAllText(tempFile).Trim();
            ExtensionMethods.FileDeleteWithRetry(tempFile);
            if (string.IsNullOrWhiteSpace(versionText))
            {
                Logger.Error(new IOException("Unable to load os version from /etc/*release* ..."));
            }
            else
            {
                FriendlyName = ExtractRegex(versionText, "^(Id|Distrib_Id)=(?<value>.*?)$", string.Empty);
                if (FriendlyName.Length != 0)
                {
                    string codeName = ExtractRegex(versionText, "^(Name|Distrib_CodeName)=(?<value>.+)$", string.Empty);
                    if (codeName.Length != 0)
                    {
                        FriendlyName += " - " + codeName;
                    }
                    Version = ExtractRegex(versionText, "^Version_Id=(?<value>.+)$", Version);
                }
            }
        }

        private static void LoadVersionFromWindows()
        {
            Name = FriendlyName = OSUtility.Windows;
            isWindows = true;
            string friendlyName = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
            if (!string.IsNullOrWhiteSpace(friendlyName))
            {
                int pos = friendlyName.IndexOf(' ');
                if (pos > 0)
                {
                    string firstWord = friendlyName.Substring(0, pos);

                    // as long as there are no extended chars, prepend Microsoft prefix
                    // some os will prepend Microsoft in another language
                    if (firstWord.Any(c => c > 126))
                    {
                        FriendlyName = friendlyName;
                    }
                    else
                    {
                        FriendlyName = "Microsoft " + friendlyName;
                    }
                }
            }

            // Windows loves to add a trailing .0 for some reason
            Version = Regex.Replace(Version, "\\.0$", string.Empty);
        }

        private static string HKLM_GetString(string path, string key)
        {
            try
            {
                using Microsoft.Win32.RegistryKey rk = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                if (rk == null) return "";
                return (string)rk.GetValue(key);
            }
            catch { return ""; }
        }

        /* WMI can hang/crash the process, especially after Windows updates, don't use for now
        private static string GetFriendlyNameFromWmi()
        {
            string result = string.Empty;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
            foreach (ManagementObject os in searcher.Get())
            {
                result = os["Caption"].ToString();
                break;
            }
            return result;
        }
        */

        /// <summary>
        /// Get a string representing the operating system
        /// </summary>
        /// <returns>String</returns>
        public static string OSString()
        {
            return $"Name: {Name}, Version: {Version}, Friendly Name: {FriendlyName}, Description: {Description}";
        }

        /// <summary>
        /// Easy way to execute processes. If the process has not finished after 60 seconds, it is forced killed.
        /// </summary>
        /// <param name="program">Program to run</param>
        /// <param name="args">Arguments</param>
        /// <param name="allowedExitCodes">Allowed exit codes, if null or empty it is not checked, otherwise a mismatch will throw an exception.</param>
        /// <returns>Output</returns>
        /// <exception cref="ApplicationException">Exit code did not match allowed exit codes</exception>
        public static string StartProcessAndWait(string program, string args, params int[] allowedExitCodes)
        {
            return StartProcessAndWait(60000, program, args, allowedExitCodes);
        }

        /// <summary>
        /// Easy way to execute processes. If the process has not finished after timeoutMilliseconds, it is forced killed.
        /// </summary>
        /// <param name="timeoutMilliseconds">Timeout in milliseconds</param>
        /// <param name="program">Program to run</param>
        /// <param name="args">Arguments</param>
        /// <param name="allowedExitCodes">Allowed exit codes, if null or empty it is not checked, otherwise a mismatch will throw an exception.</param>
        /// <returns>Output</returns>
        /// <exception cref="ApplicationException">Exit code did not match allowed exit codes</exception>
        public static string StartProcessAndWait(int timeoutMilliseconds, string program, string args, params int[] allowedExitCodes)
        {
            StringBuilder output = new StringBuilder();
            Thread thread = new Thread(new ParameterizedThreadStart((_state) =>
            {
                Logger.Info($"Executing process {program} {args}...");

                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo(program, args)
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        Verb = processVerb
                    }
                };

                process.OutputDataReceived += (object sender, DataReceivedEventArgs e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        lock (output)
                        {
                            output.Append("[OUT]: ");
                            output.AppendLine(e.Data);
                        }
                    }
                };
                process.ErrorDataReceived += (object sender, DataReceivedEventArgs e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        lock (output)
                        {
                            output.Append("[ERR]: ");
                            output.AppendLine(e.Data);
                        }
                    }
                };
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                if (!process.WaitForExit(timeoutMilliseconds))
                {
                    lock (output)
                    {
                        output.Append("[ERR]: Terminating process due to timeout");
                    }
                    process.Kill();
                }
                if (allowedExitCodes.Length != 0 && Array.IndexOf(allowedExitCodes, process.ExitCode) < 0)
                {
                    throw new ApplicationException($"Program {program} {args}: failed with exit code {process.ExitCode}, output: {output}");
                }
            }));
            thread.Start();
            int timeout = (timeoutMilliseconds < 1 ? Timeout.Infinite : timeoutMilliseconds + 5000);
            if (!thread.Join(timeout))
            {
                throw new ApplicationException("Timed out waiting for process result");
            }
            return output.ToString();
        }

        /// <summary>
        /// Check if a user name is active on the local machine
        /// </summary>
        /// <param name="userName">User name to check</param>
        /// <returns>True if user name is active, false otherwise</returns>
        public static bool UserIsActive(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName))
            {
                return false;
            }
            userName = userName.Trim();

            try
            {
                if (isWindows)
                {
                    // Windows: WMI
                    SelectQuery query = new SelectQuery("Win32_UserAccount");
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                    foreach (ManagementObject user in searcher.Get())
                    {
                        if (user["Disabled"] is null || user["Disabled"].Equals(false))
                        {
                            string possibleMatch = user["Name"]?.ToString();
                            if (possibleMatch != null && possibleMatch.Equals(userName, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                }
                else if (isLinux)
                {
                    // Linux: /etc/passwd
                    if (File.Exists("/etc/passwd"))
                    {
                        bool enabled = false;
                        string[] lines;
                        if (File.Exists("/etc/shadow"))
                        {
                            lines = File.ReadAllLines("/etc/shadow");
                            // example line:
                            // root:!$1$Fp$SSSuo3L.xA5s/kMEEIloU1:18049:0:99999:7:::
                            foreach (string[] pieces in lines.Select(l => l.Split(':')).Where(p => p.Length == 9))
                            {
                                string checkUserName = pieces[0].Trim();
                                if (checkUserName.Equals(userName))
                                {
                                    string pwdHash = pieces[1].Trim();
                                    if (pwdHash.Length != 0 && pwdHash[0] != '*' && pwdHash[0] != '!')
                                    {
                                        enabled = true;
                                        break;
                                    }
                                    else
                                    {
                                        return false;
                                    }
                                }
                            }
                        }

                        if (enabled)
                        {
                            // user is OK in shadow file, check passwd file
                            lines = File.ReadAllLines("/etc/passwd");
                            // example line:
                            // root:x:0:0:root:/root:/bin/bash
                            foreach (string[] pieces in lines.Select(l => l.Split(':')).Where(p => p.Length == 7))
                            {
                                // x means shadow file is where the password is at
                                string checkUserName = pieces[0].Trim();
                                string nologin = pieces[6];
                                if (checkUserName.Equals(userName) && nologin.IndexOf("nologin", StringComparison.OrdinalIgnoreCase) < 0 &&
                                    !nologin.Contains("/bin/false"))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                // TODO: MAC
            }
            catch (Exception ex)
            {
                Logger.Error("Error determining if user is active", ex);
            }

            return false;
        }

        /// <summary>
        /// Generate a new temporary file using TempFolder
        /// </summary>
        public static string GetTempFileName()
        {
            return Path.Combine(tempFolder, Guid.NewGuid().ToString("N") + ".tmp");
        }

        /// <summary>
        /// Add app domain exception handlers
        /// </summary>
        /// <param name="domain">Appdomain</param>
        public static void AddAppDomainExceptionHandlers(AppDomain domain)
        {
            domain.UnhandledException += (obj, ex) =>
            {
                if (ex.ExceptionObject is Exception _ex)
                {
                    Logger.Error(_ex);
                }
            };
            domain.FirstChanceException += (obj, ex) =>
            {
                //Logger.Error(ex.Exception);
            };
        }

        /// <summary>
        /// Get the current temp folder
        /// </summary>
        public static string TempFolder { get { return tempFolder; } }

        /// <summary>
        /// Are we on Windows?
        /// </summary>
        public static bool IsWindows => isWindows;

        /// <summary>
        /// Are we on Linux?
        /// </summary>
        public static bool IsLinux => isLinux;

        /// <summary>
        /// Are we on Mac?
        /// </summary>
        public static bool IsMac => isMac;

        /// <summary>
        /// Determine if system is Windows 7 or Windows Server 2008 - these systems tend to have a lot of hacks
        /// and work-arounds that are needed, especially for windows filtering platform
        /// </summary>
        public static bool IsWindows7OrServer2008
        {
            get
            {
                // Windows 7 and Server 2008 have major version of 6 and minor version of 0 or 1
                var version = System.Environment.OSVersion;
                return (version.Platform == PlatformID.Win32NT &&
                    version.Version.Major == 6 &&
                    version.Version.Minor < 2);
            }
        }

        /// <summary>
        /// Determine if system is Windows 8 or Windows Server 2012 - these systems are unable to log
        /// ip addresses is NLA is enabled
        /// </summary>
        public static bool IsWindows8OrServer2012
        {
            get
            {
                var version = System.Environment.OSVersion;
                return (version.Platform == PlatformID.Win32NT &&
                    version.Version.Major == 6 &&
                    version.Version.Minor > 1 && version.Version.Minor < 4);
            }
        }
    }

    /// <summary>
    /// Mark a class as requiring a specific operating system
    /// </summary>
    [AttributeUsage(AttributeTargets.Class)]
    public class RequiredOperatingSystemAttribute : Attribute
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="os">OS (IPBanOS.*) or null/empty if none</param>
        public RequiredOperatingSystemAttribute(string os)
        {
            RequiredOS = os?.Trim();
        }

        /// <summary>
        /// The required operating system (IPBanOS.*)
        /// </summary>
        public string RequiredOS { get; }

        /// <summary>
        /// Priority - higher priority are preferred when registering firewalls.
        /// Set to less than 0 to not include in regular firewall injection.
        /// </summary>
        public int Priority { get; set; } = 1;

        /// <summary>
        /// Major version minimum. Set to 0 or less to ignore.
        /// </summary>
        public int MajorVersionMinimum { get; set; }

        /// <summary>
        /// Minor version minimum. Set to 0 or less to ignore.
        /// </summary>
        public int MinorVersionMinimum { get; set; }

        /// <summary>
        /// Require an environment variable to exist (key=value syntax)
        /// </summary>
        public string RequireEnvironmentVariable { get; set; }

        /// <summary>
        /// Whether the current OS is a match for this attribute
        /// </summary>
        public bool IsMatch
        {
            get
            {
                OperatingSystem os = Environment.OSVersion;

                // if priority less than 0, do not match
                bool matchPriority = Priority >= 0;

                // if no os specified, do not match
                bool matchRequiredOS = !string.IsNullOrWhiteSpace(RequiredOS) &&
                    RequiredOS.Equals(OSUtility.Name, StringComparison.OrdinalIgnoreCase);

                // major version matches if param is 0 or we are less than or equal to os major version with the param
                bool matchMajorVersion = (MajorVersionMinimum <= 0 || MajorVersionMinimum <= os.Version.Major);

                // minor version matches if major version param is 0 or minor version param is 0 or major version param
                //  is less than os major version or the minor version param is less than or equal to the os minor version
                bool matchMinorVersion = (MajorVersionMinimum <= 0 || MinorVersionMinimum <= 0 || MajorVersionMinimum < os.Version.Major ||
                        MinorVersionMinimum <= os.Version.Minor);

                bool matchEnvVar = true;
                if (RequireEnvironmentVariable != null)
                {
                    string[] pieces = RequireEnvironmentVariable.Split('=');
                    if (pieces.Length == 2)
                    {
                        string value = Environment.GetEnvironmentVariable(pieces[0]);
                        if (value is null)
                        {
                            matchEnvVar = false;
                        }
                        else if (pieces[1].Length != 0)
                        {
                            matchEnvVar = pieces[1].Equals(value, StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }

                // valid is AND of all of the above
                bool valid = matchPriority && matchRequiredOS && matchMajorVersion && matchMinorVersion && matchEnvVar;

                return valid;
            }
        }
    }

    /// <summary>
    /// Apply a custom name to a class
    /// </summary>
    [AttributeUsage(AttributeTargets.Class)]
    public class CustomNameAttribute : Attribute
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Custom name</param>
        public CustomNameAttribute(string name)
        {
            Name = name;
        }

        /// <summary>
        /// Short name
        /// </summary>
        public string Name { get; set; }
    }
}

#pragma warning restore CA1416 // Validate platform compatibility
