#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;

using NLog;

#endregion Imports

namespace IPBan
{
    /// <summary>
    /// Logger
    /// </summary>
    public static class Log
    {
        private static readonly Logger logger;

        static Log()
        {
            try
            {
                LogManager.LoadConfiguration(ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath);
                logger = LogManager.GetCurrentClassLogger();
            }
            catch (Exception ex)
            {
                // only place we don't log the exception because if the logger fails to initialize... what's the point?
                Console.WriteLine("Failed to initialize logger: {0}", ex);
            }
        }

        public static void Exception(Exception ex)
        {
            Write(LogLevel.Error, "Exception: " + ex.ToString());
        }

        public static void Exception(string details, Exception ex)
        {
            Write(LogLevel.Error, details + ": " + ex.ToString());
        }

        public static void Exception(Exception ex, string format, params object[] args)
        {
            Write(LogLevel.Error, string.Format(format, args) + ": " + ex.ToString());
        }

        public static void Write(LogLevel level, string text, params object[] args)
        {
            try
            {
                logger?.Log(level, text, args);
            }
            catch
            {
            }
        }
    }
}
