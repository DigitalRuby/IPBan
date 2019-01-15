using System;
using System.Collections.Generic;
using System.Text;

namespace IPBan
{
    /// <summary>
    /// Extension methods for IPBan
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// Throw ArgumentNullException if obj is null
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Parameter name</param>
        /// <param name="message">Message</param>
        public static void ThrowIfNull(this object obj, string name = null, string message = null)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(name ?? string.Empty, message);
            }
        }
    }
}
