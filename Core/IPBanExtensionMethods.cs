using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace IPBan
{
    /// <summary>
    /// Extension methods for IPBan
    /// </summary>
    public static class IPBanExtensionMethods
    {
        private static readonly Encoding utf8EncodingNoPrefix = new UTF8Encoding(false);
        private static readonly DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

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

        /// <summary>
        /// Convert an object to string using invariant culture
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="defaultValue">Default value if null</param>
        /// <returns>String</returns>
        public static string ToStringInvariant(this object obj, string defaultValue = "")
        {
            return Convert.ToString(obj, CultureInfo.InvariantCulture) ?? defaultValue;
        }

        /// <summary>
        /// Url encode a string
        /// </summary>
        /// <param name="text">String to url encode</param>
        /// <returns>Url encoded string</returns>
        public static string UrlEncode(this string text)
        {
            return HttpUtility.UrlEncode(text ?? string.Empty);
        }

        /// <summary>
        /// Write 7 bit encoded int
        /// </summary>
        /// <param name="writer">BinaryWriter</param>
        /// <param name="value">Value</param>
        public static void Write7BitEncodedInt32(this BinaryWriter writer, int value)
        {
            // Write out an int 7 bits at a time.  The high bit of the byte,
            // when on, tells reader to continue reading more bytes.
            uint v = (uint)value;   // support negative numbers
            while (v >= 0x80)
            {
                writer.Write((byte)(v | 0x80));
                v >>= 7;
            }
            writer.Write((byte)v);
        }

        /// <summary>
        /// Read 7 bit encoded int
        /// </summary>
        /// <param name="reader">BinaryReader</param>
        /// <returns>Value</returns>
        public static int Read7BitEncodedInt32(this BinaryReader reader)
        {
            // Read out an Int32 7 bits at a time.  The high bit
            // of the byte when on means to continue reading more bytes.
            int count = 0;
            int shift = 0;
            byte b;
            do
            {
                // Check for a corrupted stream.  Read a max of 5 bytes.
                // In a future version, add a DataFormatException.
                if (shift == 5 * 7)  // 5 bytes max per Int32, shift += 7
                    throw new FormatException();

                // ReadByte handles end of stream cases for us.
                b = reader.ReadByte();
                count |= (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);
            return count;
        }

        /// <summary>
        /// Covnert a secure string to a non-secure string
        /// </summary>
        /// <param name="s">SecureString</param>
        /// <returns>Non-secure string</returns>
        public static string ToUnsecureString(this SecureString s)
        {
            if (s == null)
            {
                return null;
            }
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(s);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        /// <summary>
        /// Convert a secure string to non-secure binary data using utf-8 encoding
        /// </summary>
        /// <param name="s">SecureString</param>
        /// <returns>Binary data</returns>
        public static byte[] ToUnsecureBytes(this SecureString s)
        {
            if (s == null)
            {
                return null;
            }
            return Encoding.UTF8.GetBytes(ToUnsecureString(s));
        }

        /// <summary>
        /// Convert a string to a secure string
        /// </summary>
        /// <param name="unsecure">Plain text string</param>
        /// <returns>SecureString</returns>
        public static SecureString ToSecureString(this string unsecure)
        {
            if (unsecure == null)
            {
                return null;
            }
            SecureString secure = new SecureString();
            foreach (char c in unsecure)
            {
                secure.AppendChar(c);
            }
            return secure;
        }

        /// <summary>
        /// Get utf-8 bytes from a string
        /// </summary>
        /// <param name="s">String</param>
        /// <returns>UTF8 bytes or null if s is null</returns>
        public static byte[] ToBytesUTF8(this string s)
        {
            if (s == null)
            {
                return null;
            }
            return utf8EncodingNoPrefix.GetBytes(s);
        }

        /// <summary>
        /// Get a UTC date time from a unix epoch in milliseconds
        /// </summary>
        /// <param name="unixTimeStampSeconds">Unix epoch in milliseconds</param>
        /// <returns>UTC DateTime</returns>
        public static DateTime UnixTimeStampToDateTimeMilliseconds(this double unixTimeStampMilliseconds)
        {
            return unixEpoch.AddMilliseconds(unixTimeStampMilliseconds);
        }

        /// <summary>
        /// Get a unix timestamp in milliseconds from a DateTime
        /// </summary>
        /// <param name="dt">DateTime</param>
        /// <returns>Unix timestamp in milliseconds</returns>
        public static double UnixTimestampFromDateTimeMilliseconds(this DateTime dt)
        {
            if (dt.Kind != DateTimeKind.Utc)
            {
                dt = dt.ToUniversalTime();
            }
            return (dt - unixEpoch).TotalMilliseconds;
        }

        /// <summary>
        /// Make a task execute synchronously
        /// </summary>
        /// <param name="task">Task</param>
        public static void Sync(this Task task)
        {
            task.ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Make a task execute synchronously
        /// </summary>
        /// <param name="task">Task</param>
        /// <returns>Result</returns>
        public static T Sync<T>(this Task<T> task)
        {
            return task.ConfigureAwait(false).GetAwaiter().GetResult();
        }
    }
}
