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
using System.IO;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    public class IPBanConfigReaderWriter
    {
        /// <summary>
        /// Config locker, useful when multiple threads have spawned test services and need to sync
        /// But still works great for the normal usage of a single thread and process
        /// </summary>
        public static ActionLockerAsync Locker { get; private set; } = new ActionLockerAsync();

        /// <summary>
        /// Only use if UseFile is false, mainly for testing
        /// </summary>
        public static string GlobalConfigString { get; set; } = string.Empty; // force different from local config string for first entry

        private string localConfigString;
        private static string lastConfigValue;
        private static DateTime lastConfigWriteTime;

        /// <summary>
        /// Read config
        /// </summary>
        /// <param name="acquireLock">Whether to acquire an exclusive lock, this should always be true unless special locking patterns are used</param>
        /// <returns>Task with config string</returns>
        public async Task<string> ReadConfigAsync(bool acquireLock = true)
        {
            if (UseFile)
            {
                if (acquireLock)
                {
                    return await Locker.LockFunctionAsync(async () => await File.ReadAllTextAsync(Path));
                }
                else
                {
                    return await File.ReadAllTextAsync(Path);
                }
            }
            else if (string.IsNullOrWhiteSpace(GlobalConfigString))
            {
                throw new IOException("If not using file, globalConfigString must be populated before reading");
            }
            return GlobalConfigString;
        }

        /// <summary>
        /// Write config
        /// </summary>
        /// <param name="config">Config string to write</param>
        /// <returns>Task</returns>
        public async Task WriteConfigAsync(string config)
        {
            if (UseFile)
            {
                await Locker.LockActionAsync(async () =>
                {
                    // don't perform needless file write if config is identical
                    string existingConfig = await File.ReadAllTextAsync(Path);
                    if (existingConfig != config)
                    {
                        lastConfigValue = null;
                        await ExtensionMethods.FileWriteAllTextWithRetryAsync(Path, config);
                    }
                });
            }
            else
            {
                GlobalConfigString = config;
            }
        }

        /// <summary>
        /// Check for config change
        /// </summary>
        /// <returns>Task of config string, will be a null string if no change</returns>
        public async Task<string> CheckForConfigChange()
        {
            if (UseFile)
            {
                string result = null;
                await Locker.LockActionAsync(async () =>
                {
                    DateTime lastWriteTime = File.GetLastWriteTimeUtc(Path);
                    string currentConfig = await ReadConfigAsync(false);
                    if (lastWriteTime != lastConfigWriteTime || currentConfig != lastConfigValue)
                    {
                        lastConfigWriteTime = lastWriteTime;
                        lastConfigValue = currentConfig;
                        result = currentConfig;
                    }
                });
                return result;
            }
            else if (GlobalConfigString != localConfigString)
            {
                localConfigString = GlobalConfigString;
                return localConfigString;
            }
            return null;
        }

        /// <summary>
        /// If UseFile, the path to the config file
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Whether to use the path (file) for config. If false, a string in memory is used.
        /// </summary>
        public static bool UseFile { get; set; } = true;
    }
}
