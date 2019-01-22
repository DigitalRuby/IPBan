#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;

using NLog;
using NLog.Config;

#endregion Imports

namespace IPBan
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
                if (factory == null || factory.Configuration.AllTargets.Count == 0)
                {
                    string nlogConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "nlog.config");
                    if (!File.Exists(nlogConfigPath))
                    {
                        Console.WriteLine("Creating default nlog.config file");

                        // storing this as a resource fails to use correct string in precompiled .exe with .net core, bug with Microsoft I think
                        File.WriteAllText(nlogConfigPath, @"<?xml version=""1.0""?>
<nlog xmlns=""http://www.nlog-project.org/schemas/NLog.xsd"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" throwExceptions=""false"" internalLogToConsole=""false"" internalLogToConsoleError=""false"" internalLogLevel=""Trace"">
  <targets>
    <target name=""logfile"" xsi:type=""File"" fileName=""${basedir}/logfile.txt"" archiveNumbering=""Sequence"" archiveEvery=""Day"" maxArchiveFiles=""28"" encoding=""UTF-8""/>
    <target name=""console"" xsi:type=""Console""/>
  </targets>
  <rules>
    <logger name=""*"" minlevel=""Warn"" writeTo=""logfile""/>
    <logger name=""*"" minlevel=""Warn"" writeTo=""console""/>
  </rules>
</nlog>");
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
            }
            catch (Exception ex)
            {
                // log to console as no other logger is available
                Console.WriteLine("Failed to initialize logger: {0}", ex);
            }
        }

        /// <summary>
        /// Log current log levels
        /// </summary>
        public static void WriteLogLevels(IPBan.LogLevel level = LogLevel.Warn)
        {
            if (logger != null)
            {
                IPBanLog.Write(level, "Log levels: {0},{1},{2},{3},{4},{5}", logger.IsFatalEnabled, logger.IsErrorEnabled, logger.IsWarnEnabled, logger.IsInfoEnabled, logger.IsDebugEnabled, logger.IsTraceEnabled);
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
            Write(LogLevel.Fatal, text, args);
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Fatal(Exception ex)
        {
            Write(LogLevel.Fatal, "Exception: " + ex.ToString());
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Fatal(string text, Exception ex)
        {
            Write(LogLevel.Fatal, text + ": " + ex.ToString());
        }

        /// <summary>
        /// Log a fatal
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Fatal(Exception ex, string text, params object[] args)
        {
            Write(LogLevel.Fatal, string.Format(text, args) + ": " + ex.ToString());
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(string text, params object[] args)
        {
            Write(LogLevel.Critical, text, args);
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Critical(Exception ex)
        {
            Write(LogLevel.Critical, "Exception: " + ex.ToString());
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Critical(string text, Exception ex)
        {
            Write(LogLevel.Critical, text + ": " + ex.ToString());
        }

        /// <summary>
        /// Log a critical
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Critical(Exception ex, string text, params object[] args)
        {
            Write(LogLevel.Critical, string.Format(text, args) + ": " + ex.ToString());
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(string text, params object[] args)
        {
            Write(LogLevel.Error, text, args);
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        public static void Error(Exception ex)
        {
            Write(LogLevel.Error, "Exception: " + ex.ToString());
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="text">Text</param>
        /// <param name="ex">Error</param>
        public static void Error(string text, Exception ex)
        {
            Write(LogLevel.Error, text + ": " + ex.ToString());
        }

        /// <summary>
        /// Log an error
        /// </summary>
        /// <param name="ex">Error</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Error(Exception ex, string text, params object[] args)
        {
            Write(LogLevel.Error, string.Format(text, args) + ": " + ex.ToString());
        }

        /// <summary>
        /// Log a warn
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Warn(string text, params object[] args)
        {
            Write(LogLevel.Warn, text, args);
        }


        /// <summary>
        /// Log an info
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Info(string text, params object[] args)
        {
            Write(LogLevel.Info, text, args);
        }

        /// <summary>
        /// Log a debug
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Debug(string text, params object[] args)
        {
            Write(LogLevel.Debug, text, args);
        }

        /// <summary>
        /// Log a trace
        /// </summary>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        public static void Trace(string text, params object[] args)
        {
            Write(LogLevel.Trace, text, args);
        }

        /// <summary>
        /// Write to the log
        /// </summary>
        /// <param name="level">Log level</param>
        /// <param name="text">Text with format</param>
        /// <param name="args">Format args</param>
        private static void Write(IPBan.LogLevel level, string text, params object[] args)
        {
            try
            {
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
}
