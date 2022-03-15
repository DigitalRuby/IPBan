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
                RegexFailure = (File.Exists(regexFailureFile) && regexFailureFile.Length > 2 ? IPBanConfig.ParseRegex(File.ReadAllText(regexFailureFile)) : null),
                RegexFailureTimestampFormat = regexFailureTimestampFormat.Trim('.'),
                RegexSuccess = (File.Exists(regexSuccessFile) && regexSuccessFile.Length > 2 ? IPBanConfig.ParseRegex(File.ReadAllText(regexSuccessFile)) : null),
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
