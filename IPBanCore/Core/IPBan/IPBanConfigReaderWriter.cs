﻿/*
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

using System;
using System.IO;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Read/write config safely
    /// </summary>
    public class IPBanConfigReaderWriter
    {
        /// <summary>
        /// Config locker, useful when multiple threads have spawned test services and need to sync
        /// But still works great for the normal usage of a single thread and process
        /// </summary>
        public static ActionLockerAsync ConfigLocker { get; private set; } = new ActionLockerAsync();

        private static readonly TimeSpan forceLoadInterval = TimeSpan.FromMinutes(5.0);

        private string localConfigString;
        private string lastConfigValue;
        private DateTime lastConfigWriteTime;
        private DateTime lastConfigIntervalTime;

        /// <summary>
        /// Read config
        /// </summary>
        /// <param name="acquireLock">Whether to acquire an exclusive lock, this should always be true unless special locking patterns are used</param>
        /// <returns>Task with config string</returns>
        public async Task<string> ReadConfigAsync(bool acquireLock = true)
        {
            if (UseFile)
            {
                string result = null;
                await ExtensionMethods.RetryAsync(async () =>
                {
                    if (acquireLock)
                    {
                        result = await ConfigLocker.LockFunctionAsync(async () => await File.ReadAllTextAsync(Path));
                    }
                    else
                    {
                        result = await File.ReadAllTextAsync(Path);
                    }
                });
                return result;
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
            if (!Enabled ||
                string.IsNullOrWhiteSpace(config))
            {
                return;
            }

            config = config.Trim().Replace("\0", string.Empty).Normalize();

            if (UseFile)
            {
                await ConfigLocker.LockActionAsync(async () =>
                {
                    // don't perform needless file write if config is identical
                    string existingConfig = await File.ReadAllTextAsync(Path);
                    if (existingConfig != config)
                    {
                        string tempConfig = System.IO.Path.Combine(Path + ".tmp");
                        await ExtensionMethods.FileWriteAllTextWithRetryAsync(tempConfig, config);
                        ExtensionMethods.Retry(() => File.Move(tempConfig, Path, true));
                        lastConfigValue = null;
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
        /// <param name="forceReload">Whether to force a reload</param>
        /// <returns>Task of config string, will be a null string if no change</returns>
        public async Task<string> CheckForConfigChangeAsync(bool forceReload = false)
        {
            string result = null;
            if (!Enabled)
            {
                return result;
            }
            else if (UseFile)
            {
                // use a more exhaustive check since config files are very critical to get right
                if (!(await OSUtility.FileExistsWithFallbackAndRetryAsync(Path)))
                {
                    return result;
                }

                await ConfigLocker.LockActionAsync(async () =>
                {
                    DateTime lastWriteTime = File.GetLastWriteTimeUtc(Path);
                    string currentConfig = await ReadConfigAsync(false);
                    if (forceReload ||
                        lastWriteTime != lastConfigWriteTime ||
                        currentConfig != lastConfigValue ||

                        // if enough time has elapsed, force a reload anyway, in case of dns entries and the
                        // like in the config that need to be re-resolved
                        (IPBanService.UtcNow - lastConfigIntervalTime > forceLoadInterval))
                    {
                        lastConfigWriteTime = lastWriteTime;
                        lastConfigValue = currentConfig;
                        lastConfigIntervalTime = IPBanService.UtcNow;
                        result = currentConfig ?? throw new IOException("Failed to read config from file " + Path);
                    }
                });
                return result;
            }
            else if (GlobalConfigString != localConfigString)
            {
                localConfigString = GlobalConfigString;
                return localConfigString;
            }
            return result;
        }

        /// <summary>
        /// Whether the reader/writer is enabled
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// If UseFile, the path to the config file
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Whether to use the path (file) for config. If false, a string in memory is used.
        /// </summary>
        public bool UseFile { get; set; } = true;

        /// <summary>
        /// Only use if UseFile is false, mainly for testing to force different from local config string for first entry
        /// </summary>
        public string GlobalConfigString { get; set; } = string.Empty;
    }
}
