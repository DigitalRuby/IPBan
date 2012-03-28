using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using NLog;

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
        private static readonly Logger logger = LogManager.GetLogger("FileLogger");

        public static void Write(LogLevel level, string text, params object[] args)
        {
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
