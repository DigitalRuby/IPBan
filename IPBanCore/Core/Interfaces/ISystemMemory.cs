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

using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Provides access to total and available system memory
    /// </summary>
    public interface ISystemMemory
    {
        /// <summary>
        /// Get the available and total system memory
        /// </summary>
        /// <param name="totalMemory">Receives the total system memory, in bytes</param>/// 
        /// <param name="availableMemory">Receives the available system memory, in bytes</param>
        /// <returns>True if memory could be determined, false otherwise</returns>
        bool GetSystemMemory(out long totalMemory, out long availableMemory);
    }

    /// <summary>
    /// Default system memory implementation
    /// </summary>
    public class DefaultSystemMemory : ISystemMemory
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
            public MEMORYSTATUSEX()
            {
                this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static ISystemMemory Instance { get; } = new DefaultSystemMemory();

        /// <inheritdoc />
        public bool GetSystemMemory(out long totalMemory, out long availableMemory)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                MEMORYSTATUSEX mem = new();
                GlobalMemoryStatusEx(mem);
                availableMemory = (long)mem.ullAvailPhys;
                totalMemory = (long)mem.ullTotalPhys;
                return true;
            }
            else
            {
                // try up to 10 times to get the file open and read
                for (int i = 0; i < 10; i++)
                {
                    try
                    {
                        // example:
                        // MemTotal:       66980684 kB
                        // MemFree:        50547060 kB
                        // TODO: Consider using pinvoke...
                        using StreamReader reader = File.OpenText("/proc/meminfo");
                        string total = reader.ReadLine();
                        string available = reader.ReadLine();
                        Match totalMatch = Regex.Match(total, "[0-9]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        Match availableMatch = Regex.Match(available, "[0-9]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        totalMemory = long.Parse(totalMatch.Value, CultureInfo.InvariantCulture) * 1024;
                        availableMemory = long.Parse(availableMatch.Value, CultureInfo.InvariantCulture) * 1024;
                        return true;
                    }
                    catch
                    {
                        // don't want this to crash the thread
                        System.Threading.Thread.Sleep(100);
                    }
                }

                totalMemory = availableMemory = 0;
                Logger.Error("Unable to determine total and available RAM");
                return false;
            }
        }
    }
}
