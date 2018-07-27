using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using System.Management;
using System.Linq;

namespace IPBan
{
    // cat /etc/*-release
    public static class IPBanOS
    {
        /// <summary>
        /// Unknown operating system
        /// </summary>
        public const int Unknown = 0;

        /// <summary>
        /// Windows
        /// </summary>
        public const int Windows = 1;

        /// <summary>
        /// Linux
        /// </summary>
        public const int Linux = 2;

        /// <summary>
        /// Macintosh / OS 10
        /// </summary>
        public const int OSX = 3;

        /// <summary>
        /// Operating system (IPBanOS.Unknown, IPBanOS.Windows, IPBanOS.Linux or IPBanOS.OSX)
        /// </summary>
        public static int OS { get; private set; }

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

        private static string ExtractRegex(string input, string regex, string defaultValue)
        {
            Match m = Regex.Match(input, regex, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            if (m.Success)
            {
                return m.Groups["value"].Value.Trim('[', ']', '"', '\'', '(', ')', ' ', '\r', '\n', '\t');
            }
            return defaultValue;
        }

        static IPBanOS()
        {
            try
            {
                Version = Environment.OSVersion.VersionString;
                Description = RuntimeInformation.OSDescription;
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    OS = IPBanOS.Linux;
                    string tempFile = Path.GetTempFileName();
                    Process.Start("/bin/bash", "-c \"cat /etc/*release* > " + tempFile + "\"").WaitForExit();
                    string versionText = File.ReadAllText(tempFile);
                    Name = ExtractRegex(versionText, "^(Id|Distrib_Id)=(?<value>.*?)$", "Linux");
                    FriendlyName = ExtractRegex(versionText, "^(Name|Distrib_CodeName)=(?<value>.+)$", "Linux");
                    Version = ExtractRegex(versionText, "^Version_Id=(?<value>.+)$", Version);
                    File.Delete(tempFile);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    OS = IPBanOS.Windows;
                    Name = "Windows";
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption, Version FROM Win32_OperatingSystem");
                    foreach (var result in searcher.Get())
                    {
                        FriendlyName = result["Caption"] as string;
                        Version = result["Version"] as string;
                        break;
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    OS = IPBanOS.OSX;
                    Name = FriendlyName = "OSX";
                }
                else
                {
                    OS = IPBanOS.Unknown;
                    FriendlyName = "Unknown";
                }
            }
            catch
            {
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
        /// Easy way to execute processes. Timeout to complete is 30 seconds.
        /// </summary>
        /// <param name="program">Program to run</param>
        /// <param name="args">Arguments</param>
        /// <param name="allowedExitCode">Allowed exit codes, if empty not checked, otherwise a mismatch will throw an exception.</param>
        public static void StartProcessAndWait(string program, string args, params int[] allowedExitCode)
        {
            IPBanLog.Write(LogLevel.Information, $"Executing process {program} {args}...");

            var p = new Process
            {
                StartInfo = new ProcessStartInfo(program, args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    Verb = "runas"
                }
            };
            p.Start();
            if (!p.WaitForExit(30000))
            {
                p.Kill();
            }
            if (allowedExitCode.Length != 0 && Array.IndexOf(allowedExitCode, p.ExitCode) < 0)
            {
                throw new ApplicationException($"Program {program} {args}: failed with exit code {p.ExitCode}");
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
        /// <param name="os">OS (IPBanOS.*)</param>
        public RequiredOperatingSystemAttribute(int os)
        {
            RequiredOS = os;
        }

        /// <summary>
        /// Whether the current OS is valid for this attribute
        /// </summary>
        public bool IsValid
        {
            get { return RequiredOS == IPBanOS.OS; }
        }

        /// <summary>
        /// The required operating system (IPBanOS.*)
        /// </summary>
        public int RequiredOS { get; private set; }
    }
}
