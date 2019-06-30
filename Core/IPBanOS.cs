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
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using System.Management;
using System.Linq;

namespace DigitalRuby.IPBan
{
    // cat /etc/*-release
    public static class IPBanOS
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

        private static readonly bool isWindows;
        private static readonly bool isLinux;
        private static readonly string processVerb;
        private static readonly string tempFolder;

        private static string ExtractRegex(string input, string regex, string defaultValue)
        {
            Match m = Regex.Match(input, regex, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            if (m.Success)
            {
                return m.Groups["value"].Value.Trim('[', ']', '"', '\'', '(', ')', ' ', '\r', '\n', '\t');
            }
            return defaultValue;
        }

        private static void LoadVersionFromWmiApi()
        {
            try
            {
                // WMI API sometimes fails to initialize on .NET core on some systems, not sure why...
                // fall-back to WMI, maybe future .NET core versions will fix the bug
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption, Version FROM Win32_OperatingSystem"))
                {
                    foreach (var result in searcher.Get())
                    {
                        FriendlyName = result["Caption"] as string;
                        Version = result["Version"] as string;
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex, "Unable to load os version from wmi api");
            }
        }

        static IPBanOS()
        {
            try
            {
                tempFolder = Path.GetTempPath();
                if (string.IsNullOrWhiteSpace(tempFolder))
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        tempFolder = "c:\\temp";
                    }
                    else
                    {
                        tempFolder = "/tmp";
                    }
                }
                Directory.CreateDirectory(tempFolder);

                // start off with built in version info, this is not as detailed or nice as we like,
                //  so we try some other ways to get more detailed information
                Version = Environment.OSVersion.VersionString;
                Description = RuntimeInformation.OSDescription;

                // attempt to get detailed version info
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    isLinux = true;
                    string tempFile = IPBanOS.GetTempFileName();
                    Process.Start("/bin/bash", "-c \"cat /etc/*release* > " + tempFile + "\"").WaitForExit();
                    System.Threading.Tasks.Task.Delay(100); // wait a small bit for file to really be closed
                    string versionText = File.ReadAllText(tempFile).Trim();
                    File.Delete(tempFile);
                    if (string.IsNullOrWhiteSpace(versionText))
                    {
                        IPBanLog.Error(new IOException("Unable to load os version from /etc/*release* ..."));
                    }
                    else
                    {
                        Name = IPBanOS.Linux;
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
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    isWindows = true;
                    processVerb = "runas";
                    Name = IPBanOS.Windows;
                    string tempFile = IPBanOS.GetTempFileName();

                    // .net core WMI has a strange bug where WMI will not initialize on some systems
                    // since this is the only place where WMI is used, we can just work-around it
                    // with the wmic executable, which exists (as of 2018) on all supported Windows.
                    StartProcessAndWait("cmd", "/C wmic path Win32_OperatingSystem get Caption,Version /format:table > \"" + tempFile + "\"");
                    if (File.Exists(tempFile))
                    {
                        // try up to 10 times to read the file
                        for (int i = 0; i < 10; i++)
                        {
                            try
                            {
                                string[] lines = File.ReadAllLines(tempFile);
                                File.Delete(tempFile);
                                if (lines.Length > 1)
                                {
                                    int versionIndex = lines[0].IndexOf("Version");
                                    if (versionIndex >= 0)
                                    {
                                        FriendlyName = lines[1].Substring(0, versionIndex - 1).Trim();
                                        Version = lines[1].Substring(versionIndex).Trim();
                                        break;
                                    }
                                }
                                throw new IOException("Invalid file generated from wmic");
                            }
                            catch (Exception ex)
                            {
                                if (i < 9)
                                {
                                    System.Threading.Tasks.Task.Delay(200).Wait();
                                }
                                else
                                {
                                    IPBanLog.Error(ex, "Unable to load os version using wmic, trying wmi api...");

                                    // last resort, try wmi api
                                    LoadVersionFromWmiApi();
                                }
                            }
                        }
                    }
                    else
                    {
                        // last resort, try wmi api
                        LoadVersionFromWmiApi();
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    // TODO: Implement better for MAC
                    Name = IPBanOS.Mac;
                    FriendlyName = "OSX";
                }
                else
                {
                    Name = IPBanOS.Unknown;
                    FriendlyName = "Unknown";
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }
        }
        
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
            IPBanLog.Info($"Executing process {program} {args}...");

            var p = new Process
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
            StringBuilder output = new StringBuilder();
            p.OutputDataReceived += (object sender, DataReceivedEventArgs e) =>
            {
                lock (output)
                {
                    output.Append("[OUT]: ");
                    output.AppendLine(e.Data);
                }
            };
            p.ErrorDataReceived += (object sender, DataReceivedEventArgs e) =>
            {
                lock (output)
                {
                    output.Append("[ERR]: ");
                    output.AppendLine(e.Data);
                }
            };
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            if (!p.WaitForExit(timeoutMilliseconds))
            {
                lock (output)
                {
                    output.Append("[ERR]: Terminating process due to 60 second timeout");
                }
                p.Kill();
            }
            if (allowedExitCodes.Length != 0 && Array.IndexOf(allowedExitCodes, p.ExitCode) < 0)
            {
                throw new ApplicationException($"Program {program} {args}: failed with exit code {p.ExitCode}, output: {output}");
            }
            return output.ToString();
        }

        private static void P_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            throw new NotImplementedException();
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
                        if (user["Disabled"] == null || user["Disabled"].Equals(false))
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
                IPBanLog.Error(ex);
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
        /// Get the current temp foldre path
        /// </summary>
        public static string TempFolder { get { return tempFolder; } }
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
        /// <param name="os">OS (IPBanOS.*)</param>
        /// <param name="priority">Priority</param>
        public RequiredOperatingSystemAttribute(string os, int priority = 1)
        {
            RequiredOS = os;
            Priority = priority;
        }

        /// <summary>
        /// Whether the current OS is valid for this attribute
        /// </summary>
        public bool IsValid
        {
            get { return RequiredOS == null || RequiredOS.Equals(IPBanOS.Name, StringComparison.OrdinalIgnoreCase); }
        }

        /// <summary>
        /// The required operating system (IPBanOS.*)
        /// </summary>
        public string RequiredOS { get; }

        /// <summary>
        /// Priority, higher priority override lower priority for the same OS
        /// </summary>
        public int Priority { get; }
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
