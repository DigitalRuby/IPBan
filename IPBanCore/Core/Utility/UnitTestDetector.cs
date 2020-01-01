using System;
using System.Collections.Generic;
using System.Text;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Detect if we are running as part of a nUnit unit test, in order to work-around .NET core 3 bugs in unit tests (like razor).
    /// </summary>    
    public static class UnitTestDetector
    {
        /// <summary>
        /// True if running unit tests, false otherwise
        /// </summary>
        public static bool Running { get; }

        /// <summary>
        /// Static constructor
        /// </summary>
        static UnitTestDetector()
        {
            foreach (System.Reflection.Assembly assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.FullName.ToLowerInvariant().StartsWith("nunit.framework"))
                {
                    Running = true;
                    break;
                }
            }
        }
    }
}
