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
        private static DateTime lastConfigFileDateTime = DateTime.MinValue;

        /// <summary>
        /// Read config
        /// </summary>
        /// <returns>Task with config string</returns>
        public async Task<string> ReadConfigAsync()
        {
            if (UseFile)
            {
                return await Locker.LockFunctionAsync(async () => await File.ReadAllTextAsync(Path));
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
                DateTime lastDateTime = File.GetLastWriteTimeUtc(Path);
                if (lastDateTime > lastConfigFileDateTime)
                {
                    lastConfigFileDateTime = lastDateTime;
                    return await ReadConfigAsync();
                }
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
