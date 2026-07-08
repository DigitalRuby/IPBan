/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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

using Microsoft.Win32.TaskScheduler;

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

#pragma warning disable IDE0051 // Remove unused private members
#pragma warning disable SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Process utilities to execute a process that is detached from main process
    /// </summary>
    public static class ProcessUtility
    {
        // Process creation flags
        private const uint ZERO_FLAG = 0x00000000;
        private const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        private const uint CREATE_DEFAULT_ERROR_MODE = 0x04000000;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_PROTECTED_PROCESS = 0x00040000;
        private const uint CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
        private const uint CREATE_SEPARATE_WOW_VDM = 0x00001000;
        private const uint CREATE_SHARED_WOW_VDM = 0x00001000;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        private const uint DEBUG_PROCESS = 0x00000001;
        private const uint DETACHED_PROCESS = 0x00000008;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint INHERIT_PARENT_AFFINITY = 0x00010000;

        // Thread attributes flags
        private const uint PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
        private const uint PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        // StartupInfo flags
        private const int STARTF_USESTDHANDLES = 0x00000100;

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessID;
            public Int32 dwThreadID;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// Create a detached process
        /// </summary>
        /// <param name="fileName">File name to execute (full path)</param>
        /// <param name="arguments">Arguments</param>
        public static void CreateDetachedProcess(string fileName, string arguments)
        {
            arguments ??= string.Empty;
            Logger.Warn("Running detached process {0} {1}", fileName, arguments);

            if (OSUtility.IsWindows)
            {
                // Get the task service on the local machine
                using TaskService ts = new();

                // create task name
                var taskName = "DetachedProcess_" + Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(Path.GetFileName(fileName))));

                // remove the task if it already exists
                ts.RootFolder.DeleteTask(taskName, false);

                // create a new task definition and assign properties
                TaskDefinition td = ts.NewTask();
                td.RegistrationInfo.Description = "Detached process for " + fileName;

                // create a trigger that will run the process in 5 seconds
                td.Triggers.Add(new TimeTrigger(IPBanService.UtcNow.AddSeconds(5.0)));

                // create the action to run the process
                td.Actions.Add(new ExecAction(fileName, arguments, Path.GetDirectoryName(fileName)));

                // delete task upon completion
                td.Actions.Add(new ExecAction("schtasks.exe", "/Delete /TN \"" + taskName + "\" /F", null));

                // register the task in the root folder
                var task = ts.RootFolder.RegisterTaskDefinition(taskName, td);
                task.Run(); // just run it now

                // this code is not working on some Windows versions or from a service, the child process is still killed when the service is killed
                /*
                var processInformation = new ProcessUtility.PROCESS_INFORMATION();
                var startupInfo = new ProcessUtility.STARTUPINFO();
                var sa = new ProcessUtility.SECURITY_ATTRIBUTES();
                sa.Length = Marshal.SizeOf(sa);
                var fullArguments = $"\"{fileName}\" " + arguments;
                bool result = CreateProcess(fileName, fullArguments, ref sa, ref sa, false,
                    CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                    IntPtr.Zero, Path.GetDirectoryName(fileName), ref startupInfo, out processInformation);
                if (!result)
                {
                    Logger.Warn("Failed to create detached process for " + fileName);
                }
                */
            }
            else
            {
                // chmod via ArgumentList — no shell, so fileName goes through as a single argv
                // slot regardless of what characters it contains.
                var chmod = new ProcessStartInfo
                {
                    FileName = "sudo",
                    UseShellExecute = false,
                };
                chmod.ArgumentList.Add("chmod");
                chmod.ArgumentList.Add("+x");
                chmod.ArgumentList.Add(fileName);
                using (var p = Process.Start(chmod))
                {
                    p?.WaitForExit();
                }

                // Pipe the launch command into `at` via stdin. Without `-f`, at reads its job
                // body from stdin and copies it into the at spool — no temp file is written and
                // nothing needs cleanup.
                string commandBody = BuildAtJobBody(fileName, arguments);

                ProcessStartInfo atInfo = new()
                {
                    FileName = "at",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = Path.GetDirectoryName(fileName)
                };
                atInfo.ArgumentList.Add("now");
                using var detachedProcess = Process.Start(atInfo);
                if (detachedProcess is not null)
                {
                    detachedProcess.StandardInput.Write(commandBody);
                    detachedProcess.StandardInput.Close();
                }
            }
        }

        /// <summary>
        /// Build the shell command body that gets piped into `at` (or any compatible scheduler)
        /// to launch <paramref name="fileName"/> via sudo. fileName is wrapped in single quotes
        /// so any spaces, semicolons, backticks, or `$()` in the path are inert literals when
        /// /bin/sh later runs the spooled job. Public for testability — pure function with no
        /// side effects, safe to call cross-platform.
        /// </summary>
        public static string BuildAtJobBody(string fileName, string arguments)
        {
            var command = new StringBuilder();
            command.Append("sudo ").Append(BashEscape(fileName));
            if (!string.IsNullOrEmpty(arguments))
            {
                // arguments is operator-supplied (a shell-formed argument string by contract).
                // If callers ever start passing user-influenced data, switch to tokenized
                // arguments and BashEscape each one.
                command.Append(' ').Append(arguments);
            }
            command.Append('\n');
            return command.ToString();
        }

        /// <summary>
        /// Shell-escape a value for safe inclusion inside a single-quoted bash string.
        /// Wraps the value in single quotes and replaces any embedded single quote with '\''
        /// (close-quote, escaped quote, reopen-quote) — the canonical bash idiom.
        /// Public for testability; this is a pure function.
        /// </summary>
        public static string BashEscape(string value)
        {
            if (value is null)
            {
                return "''";
            }
            return "'" + value.Replace("'", "'\\''") + "'";
        }
    }
}

#pragma warning restore IDE0051 // Remove unused private members
#pragma warning restore SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time
