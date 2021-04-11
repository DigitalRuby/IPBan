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

#region Imports

using Microsoft.Extensions.Logging;

using NLog;
using NLog.Config;

using System;
using System.IO;
using System.Text;

#endregion Imports

namespace DigitalRuby.IPBanCore
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
    public static class Logger
    {
        private class NLogWrapper : Microsoft.Extensions.Logging.ILogger
        {
            private class EmptyDisposable : IDisposable
            {
                public void Dispose() { }
            }

            private static readonly EmptyDisposable emptyDisposable = new();
            private readonly NLog.Logger logger;

            public NLogWrapper(NLog.Logger logger)
            {
                this.logger = logger;
            }

            public IDisposable BeginScope<TState>(TState state)
            {
                return emptyDisposable;
            }

            public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel)
            {
                return logger.IsEnabled(Logger.GetNLogLevel(logLevel));
            }

            public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                NLog.LogLevel level = Logger.GetNLogLevel(logLevel);
                string message = formatter(state, exception);
                logger.Log(level, message);
            }
        }

        private static readonly Microsoft.Extensions.Logging.ILogger instance;
        private static readonly NLog.Logger nlogInstance;

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

        static Logger()
        {
            try
            {
                string nlogConfigPath = Path.Combine(AppContext.BaseDirectory, "nlog.config");
                if (!File.Exists(nlogConfigPath))
                {
                    const string defaultLogLevel = "Info";

                    Console.WriteLine("Creating default nlog.config file");

                    // storing this as a resource fails to use correct string in precompiled .exe with .net core, bug with Microsoft I think
                    string defaultNLogConfig = $@"<?xml version=""1.0""?>
<nlog xmlns=""http://www.nlog-project.org/schemas/NLog.xsd"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" throwExceptions=""false"" internalLogToConsole=""false"" internalLogToConsoleError=""false"" internalLogLevel=""Trace"">
  <targets>
    <target name=""logfile"" xsi:type=""File"" fileName=""${{basedir}}/logfile.txt"" archiveNumbering=""Sequence"" archiveEvery=""Day"" maxArchiveFiles=""28"" encoding=""UTF-8""/>
    <target name=""console"" xsi:type=""Console""/>
  </targets>
  <rules>
    <logger name=""*"" minlevel=""{defaultLogLevel}"" writeTo=""logfile""/>
    <logger name=""*"" minlevel=""{defaultLogLevel}"" writeTo=""console""/>
  </rules>
</nlog>";
                    ExtensionMethods.FileWriteAllTextWithRetry(nlogConfigPath, defaultNLogConfig);
                }
                LogFactory factory;
                if (File.Exists(nlogConfigPath))
                {
                    factory = LogManager.LoadConfiguration(nlogConfigPath);
                }
                else
                {
                    throw new IOException("Unable to create nlog configuration file, nlog.config file failed to write default config.");
                }
                nlogInstance = factory.GetCurrentClassLogger();
                instance = new NLogWrapper(nlogInstance);

                if (UnitTestDetector.Running)
                {
                    foreach (LoggingRule rule in LogManager.Configuration.LoggingRules)
                    {
                        rule.EnableLoggingForLevels(NLog.LogLevel.Trace, NLog.LogLevel.Fatal);
                    }
                    LogManager.ReconfigExistingLoggers();
                }
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
            StringBuilder b = new();
            while (ex != null)
            {
                b.Append(ex.ToString());
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
        public static void WriteLogLevels(IPBanCore.LogLevel level = LogLevel.Warn)
        {
            if (instance != null)
            {
                Logger.Log(level, IPBanService.UtcNow, "Log levels: {0},{1},{2},{3},{4},{5}",
                    nlogInstance.IsFatalEnabled, nlogInstance.IsErrorEnabled, nlogInstance.IsWarnEnabled,
                    nlogInstance.IsInfoEnabled, nlogInstance.IsDebugEnabled, nlogInstance.IsTraceEnabled);
            }
        }

        /// <summary>
        /// Map IPBan log level to NLog log level
        /// </summary>
        /// <param name="logLevel">IPBan log level</param>
        /// <returns>NLog log level</returns>
        public static NLog.LogLevel GetNLogLevel(IPBanCore.LogLevel logLevel)
        {
            return logLevel switch
            {
                IPBanCore.LogLevel.Critical => NLog.LogLevel.Fatal,
                IPBanCore.LogLevel.Debug => NLog.LogLevel.Debug,
                IPBanCore.LogLevel.Error => NLog.LogLevel.Error,
                IPBanCore.LogLevel.Information => NLog.LogLevel.Info,
                IPBanCore.LogLevel.Trace => NLog.LogLevel.Trace,
                IPBanCore.LogLevel.Warning => NLog.LogLevel.Warn,
                _ => NLog.LogLevel.Off,
            };
        }

        /// <summary>
        /// Map Microsoft log level to NLog log level
        /// </summary>
        /// <param name="logLevel">Microsoft log level</param>
        /// <returns>NLog log level</returns>
        public static NLog.LogLevel GetNLogLevel(Microsoft.Extensions.Logging.LogLevel logLevel)
        {
            return logLevel switch
            {
                Microsoft.Extensions.Logging.LogLevel.Critical => NLog.LogLevel.Fatal,
                Microsoft.Extensions.Logging.LogLevel.Debug => NLog.LogLevel.Debug,
                Microsoft.Extensions.Logging.LogLevel.Error => NLog.LogLevel.Error,
                Microsoft.Extensions.Logging.LogLevel.Information => NLog.LogLevel.Info,
                Microsoft.Extensions.Logging.LogLevel.Trace => NLog.LogLevel.Trace,
                Microsoft.Extensions.Logging.LogLevel.Warning => NLog.LogLevel.Warn,
                _ => NLog.LogLevel.Off,
            };
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Fatal(string text, params object[] args)
        {
            Log(LogLevel.Fatal, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Fatal(Exception ex)
        {
            Log(LogLevel.Fatal, IPBanService.UtcNow, "Fatal Exception: " + FormatException(ex));
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Fatal(string text, Exception ex)
        {
            Log(LogLevel.Fatal, IPBanService.UtcNow, text + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Fatal(Exception ex, string text, params object[] args)
        {
            Log(LogLevel.Fatal, IPBanService.UtcNow, string.Format(text, args) + ": " + FormatException(ex));
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
            Log(LogLevel.Fatal, ts, string.Format(text, args) + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(string text, params object[] args)
        {
            Log(LogLevel.Critical, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Critical(Exception ex)
        {
            Log(LogLevel.Critical, IPBanService.UtcNow, "Critical Exception: " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Critical(string text, Exception ex)
        {
            Log(LogLevel.Critical, IPBanService.UtcNow, text + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(Exception ex, string text, params object[] args)
        {
            Log(LogLevel.Critical, IPBanService.UtcNow, string.Format(text, args) + ": " + FormatException(ex));
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
            Log(LogLevel.Critical, ts, text + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(string text, params object[] args)
        {
            Log(LogLevel.Error, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Error(Exception ex)
        {
            Log(LogLevel.Error, IPBanService.UtcNow, "Error Exception: " + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Error(string text, Exception ex)
        {
            Log(LogLevel.Error, IPBanService.UtcNow, text + ": " + FormatException(ex));
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(Exception ex, string text, params object[] args)
        {
            Log(LogLevel.Error, IPBanService.UtcNow, string.Format(text, args) + ": " + FormatException(ex));
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
            Log(LogLevel.Error, ts, text + FormatException(ex));
        }

        /// <summary>
        /// Log a warn
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Warn(string text, params object[] args)
        {
            Log(LogLevel.Warn, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a warn
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Warn(DateTime ts, string text, params object[] args)
        {
            Log(LogLevel.Warn, ts, text, args);
        }

        /// <summary>
        /// Log an info
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Info(string text, params object[] args)
        {
            Log(LogLevel.Info, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log an info
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Info(DateTime ts, string text, params object[] args)
        {
            Log(LogLevel.Info, ts, text, args);
        }

        /// <summary>
        /// Log a debug
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Debug(string text, params object[] args)
        {
            Log(LogLevel.Debug, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a debug
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Debug(DateTime ts, string text, params object[] args)
        {
            Log(LogLevel.Debug, ts, text, args);
        }

        /// <summary>
        /// Log a trace
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Trace(string text, params object[] args)
        {
            Log(LogLevel.Trace, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Log a trace
        /// </summary>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Trace(DateTime ts, string text, params object[] args)
        {
            Log(IPBanCore.LogLevel.Trace, ts, text, args);
        }

        /// <summary>
        /// Write to the log
        /// </summary>
        /// <param name="level">Log level</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Log(IPBanCore.LogLevel level, string text, params object[] args)
        {
            Log(level, IPBanService.UtcNow, text, args);
        }

        /// <summary>
        /// Write to the log
        /// </summary>
        /// <param name="level">Log level</param>
        /// <param name="ts">Timestamp</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Log(IPBanCore.LogLevel level, DateTime ts, string text, params object[] args)
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
                nlogInstance?.Log(GetNLogLevel(level), text, args);
            }
            catch
            {
            }
        }

        /// <summary>
        /// Internal access to the logger
        /// </summary>
        public static Microsoft.Extensions.Logging.ILogger Instance { get { return instance; } }
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
        /// <param name="external">Whether this log came from an external source</param>
        /// <param name="failedLoginThreshold">Failed login threshold or 0 for default</param>
        /// <param name="logLevel">Log level when the event is logged</param>
        public IPAddressLogEvent(string ipAddress, string userName, string source,
            int count, IPAddressEventType type, DateTime timestamp = default, bool external = false,
            int failedLoginThreshold = 0, LogLevel logLevel = LogLevel.Warning)
        {
            // normalize ip address if possible
            if (System.Net.IPAddress.TryParse(ipAddress, out System.Net.IPAddress parsedIPAddress))
            {
                IPAddress = parsedIPAddress.ToString();
            }
            else
            {
                IPAddress = ipAddress;
            }
            UserName = userName;
            Source = source;
            Count = count;
            Type = type;
            Timestamp = (timestamp == default ? IPBanService.UtcNow : timestamp);
            External = external;
            FailedLoginThreshold = failedLoginThreshold;
            LogLevel = logLevel;
        }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return $"IP: {IPAddress}, UserName: {UserName}, Source: {Source}, Count: {Count}, Type: {Type}, Timestamp: {Timestamp}";
        }

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
        /// Whether this event was from an external source
        /// </summary>
        public bool External { get; set; }

        /// <summary>
        /// Timestamp of the event
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Event flag
        /// </summary>
        public IPAddressEventType Type { get; set; }

        /// <summary>
        /// Failed login threshold or 0 for default
        /// </summary>
        public int FailedLoginThreshold { get; set; }

        /// <summary>
        /// Log level
        /// </summary>
        public LogLevel LogLevel { get; set; }
    }
}
