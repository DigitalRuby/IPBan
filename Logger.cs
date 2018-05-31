#region Imports

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using NLog;

#endregion Imports

namespace IPBan
{
    public enum LogLevel
    {
        Info,
        Warning,
        Error
    }

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
                logger = LogManager.GetLogger("FileLogger");
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
            if (logger == null)
            {
                return;
            }

            switch (level)
            {
                case LogLevel.Info:
                    logger.Info(text, args);
                    break;

                case LogLevel.Warning:
                    logger.Warn(text, args);
                    break;

                case LogLevel.Error:
                    logger.Error(text, args);
                    break;
            }
        }
    }
}
