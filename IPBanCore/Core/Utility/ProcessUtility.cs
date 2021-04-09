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

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

#pragma warning disable IDE0059 // Unnecessary assignment of a value
#pragma warning disable IDE0051 // Remove unused private members

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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
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
        /// <param name="fileName">File name to execute</param>
        /// <param name="arguments">Arguments</param>
        public static void CreateDetachedProcess(string fileName, string arguments)
        {
            arguments ??= string.Empty;
            Logger.Warn("Running detached process {0} {1}", fileName, arguments);

            if (OSUtility.IsWindows)
            {
                var processInformation = new ProcessUtility.PROCESS_INFORMATION();
                var startupInfo = new ProcessUtility.STARTUPINFO();
                var sa = new ProcessUtility.SECURITY_ATTRIBUTES();
                sa.Length = Marshal.SizeOf(sa);
                CreateProcess(null, "\"" + fileName + "\" " + arguments, ref sa, ref sa, false,
                    DETACHED_PROCESS,
                    IntPtr.Zero, Path.GetDirectoryName(fileName), ref startupInfo, out processInformation);
            }
            else
            {
                // ensure process is executable
                OSUtility.StartProcessAndWait("sudo", "chmod +x \"" + fileName + "\"");

                // use Linux at, should have been installed earlier
                ProcessStartInfo info = new()
                {
                    Arguments = "-c \"echo sudo \\\"" + fileName + "\\\" " + arguments.Replace("\"", "\\\"") + " | at now\"",
                    CreateNoWindow = true,
                    FileName = "/bin/bash",
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = Path.GetDirectoryName(fileName)
                };

                // start detached process, do not dispose
                using Process process = Process.Start(info);
            }
        }
    }
}

#pragma warning restore IDE0059 // Unnecessary assignment of a value
#pragma warning restore IDE0051 // Remove unused private members
