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

        private static readonly Lazy<OSUtility> instance = new Lazy<OSUtility>(() =>
        {
            OSUtility os = new OSUtility();
            os.Initialize();
            return os;
        });

        /// <summary>
        /// Singleton. Setting static variables in a static constructor especially with threads has proven
        /// problematic, so making this a singleton object instead.
        /// </summary>
        public static OSUtility Instance { get { return instance.Value; } }

        /// <summary>
        /// Operating system name (i.e. Windows, Linux or OSX)
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Operating system cpu architecture (i.e. x86 or x64)
        /// </summary>
        public string CpuArchitecture { get; private set; }

        /// <summary>
        /// Operating system version
        /// </summary>
        public string Version { get; private set; }

        /// <summary>
        /// Operating system friendly/code name
        /// </summary>
        public string FriendlyName { get; private set; }

        /// <summary>
        /// Operating system description
        /// </summary>
        public string Description { get; private set; }

        private bool isWindows;
        private bool isLinux;
        private bool isMac;

        private string processVerb;
        private string tempFolder;

        private string ExtractRegex(string input, string regex, string defaultValue)
        {
            Match m = Regex.Match(input, regex, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            if (m.Success)
            {
                return m.Groups["value"].Value.Trim('[', ']', '"', '\'', '(', ')', ' ', '\r', '\n', '\t');
            }
            return defaultValue;
        }

        private void LoadVersionFromWmiApi()
        {
            Logger.Info("Attempting to retrieve os version from WMI api...");

            // use local vars, attempting to set property in a static constructor in a thread hangs the process
            string friendlyName = null;
            string version = null;

            // in case this hangs after os reboot, put a 5 second timeout on the call
            Thread thread = new Thread(new ThreadStart(() =>
            {
                try
                {
                    // WMI API sometimes fails to initialize on .NET core on some systems, not sure why...
                    // fall-back to WMI, maybe future .NET core versions will fix the bug
                    using ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption, Version FROM Win32_OperatingSystem");
                    foreach (var result in searcher.Get())
                    {
                        friendlyName = result["Caption"] as string;
                        version = result["Version"] as string;
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Error loading os info from WMI API");
                }
            }));
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            if (!thread.Join(5000))
            {
                throw new ApplicationException("Timed out loading os info from WMI API");
            }
            if (friendlyName is null || version is null)
            {
                throw new IOException("WMI did not return the name and version");
            }
            FriendlyName = friendlyName;
            Version = version;
        }

        private void LoadVersionFromWmic()
        {
            string tempFile = GetTempFileName();
            
            // .net core WMI has a strange bug where WMI will not initialize on some systems
            // since this is the only place where WMI is used, we can just work-around it
            // with the wmic executable, which exists (as of 2018) on all supported Windows.
            // this process can hang and fail to run after windows update or other cases on system restart,
            // so put a short timeout in and fallback to WMI api if needed
            Exception lastError = null;

            Logger.Info("Attempting to load os info from wmic");

            // attempt to run wmic to generate the info we want
            StartProcessAndWait(5000, "cmd", "/C wmic path Win32_OperatingSystem get Caption,Version /format:table > \"" + tempFile + "\"");

            // try up to 10 times to read the file in case file is still in use
            try
            {
                for (int i = 0; i < 10; i++)
                {
                    try
                    {
                        // if this throws, we will try again
                        string[] lines = File.ReadAllLines(tempFile);

                        // if we have enough lines, try to parse them out
                        if (lines.Length > 1)
                        {
                            int versionIndex = lines[0].IndexOf("Version");
                            if (versionIndex >= 0)
                            {
                                FriendlyName = lines[1].Substring(0, versionIndex - 1).Trim();
                                Version = lines[1].Substring(versionIndex).Trim();
                                return;
                            }
                        }

                        throw new InvalidDataException("Invalid file generated by wmic");
                    }
                    catch (Exception ex)
                    {
                        lastError = ex;
                        if (ex is InvalidDataException)
                        {
                            break;
                        }
                    }
                    Thread.Sleep(200);
                }
            }
            finally
            {
                ExtensionMethods.FileDeleteWithRetry(tempFile);
            }
            throw new ApplicationException("Unable to load os version using wmic", lastError);
        }

        private void LoadOSInfo()
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
            CpuArchitecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
            Version = Environment.OSVersion.Version.ToString();
            Description = RuntimeInformation.OSDescription;

            // attempt to get detailed version info
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Name = FriendlyName = OSUtility.Linux;
                isLinux = true;
                string tempFile = GetTempFileName();
                Process.Start("/bin/bash", "-c \"cat /etc/*release* > " + tempFile + "\"").WaitForExit();
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
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Name = FriendlyName = OSUtility.Windows;
                isWindows = true;
                processVerb = "runas";
                try
                {
                    LoadVersionFromWmic();
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Failed to load os info from wmic");

                    // last resort, try wmi api
                    LoadVersionFromWmiApi();
                }
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
        }

        private int osInfoRetryCount;

        private void LoadOSInfoWithRetryLoop()
        {
            try
            {
                LoadOSInfo();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error loading os info");

                // try up to 100 times to load the os info
                if (++osInfoRetryCount < 100)
                {
                    ThreadPool.QueueUserWorkItem(state =>
                    {
                        Thread.Sleep(10000);
                        LoadOSInfoWithRetryLoop();
                    });
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        private OSUtility()
        {
        }

        private void Initialize()
        {
            // perform initialize after constructor to avoid weird clr issues and freezing
            LoadOSInfoWithRetryLoop();
        }

        /// <summary>
        /// Get a string representing the operating system
        /// </summary>
        /// <returns>String</returns>
        public string OSString()
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
        public string StartProcessAndWait(string program, string args, params int[] allowedExitCodes)
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
        public string StartProcessAndWait(int timeoutMilliseconds, string program, string args, params int[] allowedExitCodes)
        {
            StringBuilder output = new StringBuilder();
            Task task = Task.Run(() =>
            {
                Logger.Info($"Executing process {program} {args}...");

                var process = new Process
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
                    lock (output)
                    {
                        output.Append("[OUT]: ");
                        output.AppendLine(e.Data);
                    }
                };
                process.ErrorDataReceived += (object sender, DataReceivedEventArgs e) =>
                {
                    lock (output)
                    {
                        output.Append("[ERR]: ");
                        output.AppendLine(e.Data);
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
            });
            if (!task.Wait(timeoutMilliseconds + 5000))
            {
                if (task.IsFaulted && task.Exception != null)
                {
                    throw task.Exception;
                }
                throw new ApplicationException("Timed out waiting for process result");
            }
            return output.ToString();
        }

        /// <summary>
        /// Check if a user name is active on the local machine
        /// </summary>
        /// <param name="userName">User name to check</param>
        /// <returns>True if user name is active, false otherwise</returns>
        public bool UserIsActive(string userName)
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
        public string GetTempFileName()
        {
            return Path.Combine(tempFolder, Guid.NewGuid().ToString("N") + ".tmp");
        }

        /// <summary>
        /// Check if this process is running on Windows in an in process instance in IIS
        /// </summary>
        /// <returns>True if Windows and in an in process instance on IIS, false otherwise</returns>
        public static bool IsRunningInProcessIIS()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return false;
            }

            string processName = Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().ProcessName);
            return (processName.Contains("w3wp", StringComparison.OrdinalIgnoreCase) ||
                processName.Contains("iisexpress", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Add app domain exception handlers
        /// </summary>
        /// <param name="domain">Appdomain</param>
        public void AddAppDomainExceptionHandlers(AppDomain domain)
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
        /// Get the current temp foldre path
        /// </summary>
        public string TempFolder { get { return tempFolder; } }

        /// <summary>
        /// Are we on Windows?
        /// </summary>
        public bool IsWindows => isWindows;

        /// <summary>
        /// Are we on Linux?
        /// </summary>
        public bool IsLinux => isLinux;

        /// <summary>
        /// Are we on Mac?
        /// </summary>
        public bool IsMac => isMac;
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
            get { return RequiredOS is null || RequiredOS.Equals(OSUtility.Instance.Name, StringComparison.OrdinalIgnoreCase); }
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
