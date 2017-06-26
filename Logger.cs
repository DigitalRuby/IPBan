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
                Console.WriteLine("Failed to initialize logger: {0}", ex);
            }
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
