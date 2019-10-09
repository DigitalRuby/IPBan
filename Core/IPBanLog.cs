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

#region Imports

using NLog;
using System;
using System.Configuration;
using System.IO;
using System.Reflection;
using System.Text;

#endregion Imports

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// Log levels
    /// </summary>
    public enum LogLevel
    {
        /// <summary>
        /// Trace / Diagnostic
        /// </summary>
        Trace,

        /// <summary>
        /// Trace / Diagnostic
        /// </summary>
        Diagnostic = Trace,

        /// <summary>
        /// Debug
        /// </summary>
        Debug,

        /// <summary>
        /// Information / Info
        /// </summary>
        Information,

        /// <summary>
        /// Information / Info
        /// </summary>
        Info = Information,

        /// <summary>
        /// Warning / Warn
        /// </summary>
        Warning,

        /// <summary>
        /// Warning / Warn
        /// </summary>
        Warn = Warning,

        /// <summary>
        /// Error / Exception
        /// </summary>
        Error,

        /// <summary>
        /// Error / Exception
        /// </summary>
        Exception = Error,

        /// <summary>
        /// Critical / Fatal
        /// </summary>
        Critical,

        /// <summary>
        /// Critical / Fatal
        /// </summary>
        Fatal = Critical,

        /// <summary>
        /// Off / None
        /// </summary>
        Off,

        /// <summary>
        /// Off / None
        /// </summary>
        None = Off
    }

    /// <summary>
    /// IPBan logger. Will never throw exceptions.
    /// Currently the IPBan logger uses NLog internally, so make sure it is setup in your app.config file or nlog.config file.
    /// </summary>
    public static class IPBanLog
    {
        private static readonly Logger logger;

        /* // makes nlog go haywire, revisit later
        private static readonly CustomTimeSource timeSource = new CustomTimeSource();

        private class CustomTimeSource : NLog.Time.TimeSource
        {
            private TimeZoneInfo zoneInfo = TimeZoneInfo.Utc;

            [Required]
            public string Zone
            {
                get { return zoneInfo.DisplayName; }
                set { zoneInfo = TimeZoneInfo.FindSystemTimeZoneById(value); }
            }

            public override DateTime Time => IPBanService.UtcNow;

            public override DateTime FromSystemTime(DateTime systemTime)
            {
                return systemTime.ToUniversalTime();
            }

            public DateTime CurrentTime { get; set; } = IPBanService.UtcNow;
        }
        */

        static IPBanLog()
        {
            try
            {
                LogFactory factory = null;
                try
                {
                    factory = LogManager.LoadConfiguration(ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath);
                }
                catch
                {
                    // if no config, exception is thrown that is OK
                }
                if (factory is null || factory.Configuration.AllTargets.Count == 0)
                {
                    string nlogConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "nlog.config");
                    if (!File.Exists(nlogConfigPath))
                    {
                        string logLevel = "Warn";
                        foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies())
                        {
                            if (a.FullName.IndexOf("nunit.framework", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                logLevel = "Trace";
                                break;
                            }
                        }

                        Console.WriteLine("Creating default nlog.config file");

                        // storing this as a resource fails to use correct string in precompiled .exe with .net core, bug with Microsoft I think
                        string defaultNLogConfig = $@"<?xml version=""1.0""?>
<nlog xmlns=""http://www.nlog-project.org/schemas/NLog.xsd"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" throwExceptions=""false"" internalLogToConsole=""false"" internalLogToConsoleError=""false"" internalLogLevel=""Trace"">
  <targets>
    <target name=""logfile"" xsi:type=""File"" fileName=""${{basedir}}/logfile.txt"" archiveNumbering=""Sequence"" archiveEvery=""Day"" maxArchiveFiles=""28"" encoding=""UTF-8""/>
    <target name=""console"" xsi:type=""Console""/>
  </targets>
  <rules>
    <logger name=""*"" minlevel=""{logLevel}"" writeTo=""logfile""/>
    <logger name=""*"" minlevel=""{logLevel}"" writeTo=""console""/>
  </rules>
</nlog>";
                        IPBanExtensionMethods.FileWriteAllTextWithRetry(nlogConfigPath, defaultNLogConfig);
                    }
                    if (File.Exists(nlogConfigPath))
                    {
                        factory = LogManager.LoadConfiguration(nlogConfigPath);
                    }
                    else
                    {
                        throw new IOException("Unable to create nlog configuration file, nlog.config file failed to write default config.");
                    }
                }
                logger = factory.GetCurrentClassLogger();
                //NLog.Time.TimeSource.Current = timeSource;
            }
            catch (Exception ex)
            {
                // log to console as no other logger is available
                Console.WriteLine("Failed to initialize logger: {0}", ex);
            }
        }

        private static string FormatException(Exception ex)
        {
            StringBuilder b = new StringBuilder();
            while (ex != null)
            {
                b.AppendFormat(ex.ToString());
                if (ex.InnerException != null)
                {
                    b.AppendLine("---");
                }
                ex = ex.InnerException;
            }
            return b.ToString();
        }

        /// <summary>
        /// Log current log levels
        /// </summary>
        public static void WriteLogLevels(IPBan.LogLevel level = LogLevel.Warn)
        {
            if (logger != null)
            {
                IPBanLog.Write(level, IPBanService.UtcNow, "Log levels: {0},{1},{2},{3},{4},{5}", logger.IsFatalEnabled, logger.IsErrorEnabled, logger.IsWarnEnabled, logger.IsInfoEnabled, logger.IsDebugEnabled, logger.IsTraceEnabled);
            }
        }

        /// <summary>
        /// Map IPBan log level to NLog log level
        /// </summary>
        /// <param name="logLevel">IPBan log level</param>
        /// <returns>NLog log level</returns>
        public static NLog.LogLevel GetNLogLevel(IPBan.LogLevel logLevel)
        {
            switch (logLevel)
            {
                case IPBan.LogLevel.Critical: return NLog.LogLevel.Fatal;
                case IPBan.LogLevel.Debug: return NLog.LogLevel.Debug;
                case IPBan.LogLevel.Error: return NLog.LogLevel.Error;
                case IPBan.LogLevel.Information: return NLog.LogLevel.Info;
                case IPBan.LogLevel.Trace: return NLog.LogLevel.Trace;
                case IPBan.LogLevel.Warning: return NLog.LogLevel.Warn;
                default: return NLog.LogLevel.Off;
            }
        }

        /// <summary>
        /// Map Microsoft log level to NLog log level
        /// </summary>
        /// <param name="logLevel">Microsoft log level</param>
        /// <returns>NLog log level</returns>
        public static NLog.LogLevel GetNLogLevel(Microsoft.Extensions.Logging.LogLevel logLevel)
        {
            switch (logLevel)
            {
                case Microsoft.Extensions.Logging.LogLevel.Critical: return NLog.LogLevel.Fatal;
                case Microsoft.Extensions.Logging.LogLevel.Debug: return NLog.LogLevel.Debug;
                case Microsoft.Extensions.Logging.LogLevel.Error: return NLog.LogLevel.Error;
                case Microsoft.Extensions.Logging.LogLevel.Information: return NLog.LogLevel.Info;
                case Microsoft.Extensions.Logging.LogLevel.Trace: return NLog.LogLevel.Trace;
                case Microsoft.Extensions.Logging.LogLevel.Warning: return NLog.LogLevel.Warn;
                default: return NLog.LogLevel.Off;
            }
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Fatal(string text, params object[] args)
        {
            Write(LogLevel.Fatal, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Fatal(Exception ex)
        {
            Write(LogLevel.Fatal, IPBanService.UtcNow, "Fatal Exception: " + FormatException(ex));
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Fatal(string text, Exception ex)
        {
            Write(LogLevel.Fatal, IPBanService.UtcNow, text + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Fatal(Exception ex, string text, params object[] args)
        {
            Write(LogLevel.Fatal, IPBanService.UtcNow, string.Format(text, args) + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Fatal(Exception ex, DateTime ts, string text, params object[] args)
        {
            Write(LogLevel.Fatal, ts, string.Format(text, args) + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(string text, params object[] args)
        {
            Write(LogLevel.Critical, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Critical(Exception ex)
        {
            Write(LogLevel.Critical, IPBanService.UtcNow, "Critical Exception: " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Critical(string text, Exception ex)
        {
            Write(LogLevel.Critical, IPBanService.UtcNow, text + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(Exception ex, string text, params object[] args)
        {
            Write(LogLevel.Critical, IPBanService.UtcNow, string.Format(text, args) + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(Exception ex, DateTime ts, string text, params object[] args)
        {
            text = (string.IsNullOrWhiteSpace(text) ? string.Empty : string.Format(text, args) + " : ");
            Write(LogLevel.Critical, ts, text + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(string text, params object[] args)
        {
            Write(LogLevel.Error, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Error(Exception ex)
        {
            Write(LogLevel.Error, IPBanService.UtcNow, "Error Exception: " + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Error(string text, Exception ex)
        {
            Write(LogLevel.Error, IPBanService.UtcNow, text + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(Exception ex, string text, params object[] args)
        {
            Write(LogLevel.Error, IPBanService.UtcNow, string.Format(text, args) + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(Exception ex, DateTime ts, string text, params object[] args)
        {
            text = (string.IsNullOrWhiteSpace(text) ? string.Empty : string.Format(text, args) + " : ");
            Write(LogLevel.Error, ts, text + FormatException(ex));
        }

        /// <summary>
        /// Log a warn
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Warn(string text, params object[] args)
        {
            Write(LogLevel.Warn, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a warn
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Warn(DateTime ts, string text, params object[] args)
        {
            Write(LogLevel.Warn, ts, text, args);
        }

        /// <summary>
        /// Log an info
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Info(string text, params object[] args)
        {
            Write(LogLevel.Info, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log an info
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Info(DateTime ts, string text, params object[] args)
        {
            Write(LogLevel.Info, ts, text, args);
        }

        /// <summary>
        /// Log a debug
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Debug(string text, params object[] args)
        {
            Write(LogLevel.Debug, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a debug
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Debug(DateTime ts, string text, params object[] args)
        {
            Write(LogLevel.Debug, ts, text, args);
        }

        /// <summary>
        /// Log a trace
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Trace(string text, params object[] args)
        {
            Write(LogLevel.Trace, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a trace
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Trace(DateTime ts, string text, params object[] args)
        {
            Write(LogLevel.Trace, ts, text, args);
        }

        /// <summary>
        /// Write to the log
        /// </summary>
        /// <param name="level">Log level</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        private static void Write(IPBan.LogLevel level, string text, params object[] args)
        {
            Write(level, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Write to the log
        /// </summary>
        /// <param name="level">Log level</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        private static void Write(IPBan.LogLevel level, DateTime ts, string text, params object[] args)
        {
            try
            {

#if DEBUG

                if (level == LogLevel.Error || level == LogLevel.Critical || level == LogLevel.Fatal)
                {
                    // System.Diagnostics.Debugger.Break();
                }

#endif

                //timeSource.CurrentTime = ts;
                logger?.Log(GetNLogLevel(level), text, args);
            }
            catch
            {
            }
        }

        /// <summary>
        /// Internal access to the logger
        /// </summary>
        public static Logger Logger { get { return logger; } }
    }

    /// <summary>
    /// Information about an ip address from a log entry
    /// </summary>
    public class IPAddressLogEvent
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="userName">User name</param>
        /// <param name="source">Source</param>
        /// <param name="count">How many messages were aggregated, 1 for no aggregation</param>
        /// <param name="type">Event type</param>
        /// <param name="timestamp">Timestamp of the event, default for current timestamp</param>
        public IPAddressLogEvent(string ipAddress, string userName, string source, int count, IPAddressEventType type, DateTime timestamp = default)
        {
            IPAddress = ipAddress;
            UserName = userName;
            Source = source;
            Count = count;
            Type = type;
            Timestamp = (timestamp == default ? IPBanService.UtcNow : timestamp);
            FoundMatch = true;
        }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return $"IP: {IPAddress}, Match: {FoundMatch}, UserName: {UserName}, Source: {Source}, Count: {Count}, Type: {Type}, Timestamp: {Timestamp}";
        }

        /// <summary>
        /// Whether a match was found
        /// </summary>
        public bool FoundMatch { get; set; }

        /// <summary>
        /// IP address
        /// </summary>
        public string IPAddress { get; set; }

        /// <summary>
        /// User name
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Source
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// How many messages were aggregated, 1 for no aggregation. Can be set to 0 if count is unknown or from an external source.
        /// </summary>
        public int Count { get; set; }

        /// <summary>
        /// Timestamp of the event
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Event flag
        /// </summary>
        public IPAddressEventType Type { get; set; }
    }
}
