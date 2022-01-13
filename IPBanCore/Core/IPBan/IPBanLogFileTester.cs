using System;
using System.IO;
using System.Collections.Generic;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Test log files
    /// </summary>
    public static class IPBanLogFileTester
    {
        private class LogFileWriter : IIPAddressEventHandler
        {
            public void AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events)
            {
                foreach (var evt in events)
                {
                    Console.WriteLine(evt);
                }
            }
        }

        /// <summary>
        /// Test a log file
        /// </summary>
        /// <param name="fileName">Log file</param>
        public static void RunLogFileTest(string fileName,
            string regexFailureFile,
            string regexFailureTimestampFormat,
            string regexSuccessFile,
            string regexSuccessTimestampFormat)
        {
            IPBanLogFileScanner scanner = new(new()
            {
                Dns = new DefaultDnsLookup(),
                FailedLoginThreshold = 3,
                FailedLogLevel = LogLevel.Warning,
                LoginHandler = new LogFileWriter(),
                MaxFileSizeBytes = 0,
                PathAndMask = fileName.Trim(),
                PingIntervalMilliseconds = 0,
                RegexFailure = IPBanConfig.ParseRegex(File.ReadAllText(regexFailureFile)),
                RegexFailureTimestampFormat = regexFailureTimestampFormat.Trim('.'),
                RegexSuccess = IPBanConfig.ParseRegex(File.ReadAllText(regexSuccessFile)),
                RegexSuccessTimestampFormat = regexSuccessTimestampFormat.Trim('.'),
                Source = "test",
                SuccessfulLogLevel = LogLevel.Warning
            });

            // start with empty file
            File.Move(fileName, fileName + ".temp");
            File.WriteAllText(fileName, string.Empty);

            // read the empty file
            scanner.ProcessFiles();

            // get rid of the empty file
            File.Delete(fileName);

            // put the full file back
            File.Move(fileName + ".temp", fileName);

            // now the scanner will process the entire file
            scanner.ProcessFiles();
        }
    }
}
