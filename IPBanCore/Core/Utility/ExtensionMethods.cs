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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using System.Xml.Serialization;

#endregion Imports

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Extension methods for IPBan
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// UTF8 encoder without prefix bytes
        /// </summary>
        public static readonly Encoding Utf8EncodingNoPrefix = new UTF8Encoding(false);

        private static readonly DateTime unixEpoch = new(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        private static readonly XmlSerializerNamespaces emptyXmlNs = new();

        private static readonly System.Text.Json.JsonSerializerOptions jsonOptions = new()
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault,
            IgnoreReadOnlyFields = true,
            IgnoreReadOnlyProperties = true
        };

        static ExtensionMethods()
        {
            emptyXmlNs.Add("", "");
        }

        /// <summary>
        /// Throw ArgumentNullException if obj is null
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Parameter name</param>
        /// <param name="message">Message</param>
        /// <returns>Object</returns>
        public static T ThrowIfNull<T>(this T obj, string name = null, string message = null)
        {
            if (obj is null)
            {
                throw new ArgumentNullException(name ?? string.Empty, message);
            }
            return obj;
        }

        /// <summary>
        /// Throw ArgumentException if obj is null
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Parameter name</param>
        /// <param name="message">Message</param>
        /// <returns>Object</returns>
        public static T ThrowArgumentExceptionIfNull<T>(this T obj, string name = null, string message = null)
        {
            if (obj is null)
            {
                throw new ArgumentException(name ?? string.Empty, message);
            }
            return obj;
        }

        /// <summary>
        /// Throw ArgumentNullException if obj is null or white space
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Parameter name</param>
        /// <param name="message">Message</param>
        public static void ThrowIfNullOrWhiteSpace(this string obj, string name = null, string message = null)
        {
            if (string.IsNullOrWhiteSpace(obj))
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
        /// Convert utf-8 bytes to string
        /// </summary>
        /// <param name="bytes">Bytes</param>
        /// <returns>Utf-8 decoded string</returns>
        public static string ToStringUTF8(this byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        private static readonly ConcurrentDictionary<Type, XmlSerializer> toStringXmlSerializers = new();

        /// <summary>
        /// Convert an object to an xml fragment
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>Xml fragment or null if obj is null</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static string ToStringXml(this object obj)
        {
            if (obj is null)
            {
                return null;
            }

            StringWriter xml = new();
            XmlSerializer serializer = toStringXmlSerializers.GetOrAdd(obj.GetType(), new XmlSerializer(obj.GetType()));
            using (XmlWriter writer = XmlWriter.Create(xml, new XmlWriterSettings { Indent = true, NewLineHandling = NewLineHandling.None, OmitXmlDeclaration = true }))
            {
                serializer.Serialize(writer, obj, emptyXmlNs);
            }
            return xml.ToString();
        }

        /// <summary>
        /// Convert DateTime to Iso8601 string with Z suffix
        /// </summary>
        /// <param name="dt">DateTime</param>
        /// <returns>Iso 8601 string</returns>
        public static string ToStringIso8601(this DateTime dt)
        {
            return dt.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture)
                .Replace(IPBanFilter.ItemDelimiterString, string.Empty);
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
        /// Attempt to parse a long
        /// </summary>
        /// <param name="text">Text</param>
        /// <returns>Parsed long or 0 if failure</returns>
        public static long ToLongInvariant(this string text)
        {
            if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long value))
            {
                return value;
            }
            return 0;
        }

        /// <summary>
        /// Covnert a secure string to a non-secure string
        /// </summary>
        /// <param name="s">SecureString</param>
        /// <returns>Non-secure string</returns>
        public static string ToUnsecureString(this SecureString s)
        {
            if (s is null)
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
            if (s is null)
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
            if (unsecure is null)
            {
                return null;
            }
            SecureString secure = new();
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
            if (s is null)
            {
                return null;
            }
            return Utf8EncodingNoPrefix.GetBytes(s);
        }

        /// <summary>
        /// Get a sha256 hex string from a string
        /// </summary>
        /// <param name="s">String</param>
        /// <returns>Sha-256 hex string</returns>
        public static string ToSHA256String(this string s)
        {
            s ??= string.Empty;
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
        }

        /// <summary>
        /// Convert bytes to hex string
        /// </summary>
        /// <param name="bytes">Bytes</param>
        /// <returns>Hex string</returns>
        public static string ToHexString(this byte[] bytes)
        {
            return Convert.ToHexString(bytes);
        }

        /// <summary>
        /// Convert hex string to bytes
        /// </summary>
        /// <param name="s">String in hex format</param>
        /// <returns>Bytes</returns>
        public static byte[] ToBytesFromHex(this string s)
        {
            var bytes = new byte[16];
            for (int i = 0; i < s.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(s.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Convert an object to an http header value string
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>Http header value string</returns>
        public static string ToHttpHeaderString(this object obj)
        {
            if (obj is null)
            {
                return string.Empty;
            }
            else if (obj is SecureString secureString)
            {
                return secureString.ToUnsecureString();
            }
            return obj.ToStringInvariant();
        }

        /// <summary>
        /// Get a UTC date time from a unix epoch in milliseconds
        /// </summary>
        /// <param name="unixTimeStampMilliseconds">Unix epoch in milliseconds</param>
        /// <returns>UTC DateTime</returns>
        public static DateTime ToDateTimeUnixMilliseconds(this double unixTimeStampMilliseconds)
        {
            return unixEpoch.AddMilliseconds(unixTimeStampMilliseconds);
        }

        /// <summary>
        /// Get a UTC date time from a unix epoch in milliseconds
        /// </summary>
        /// <param name="unixTimeStampMilliseconds">Unix epoch in milliseconds</param>
        /// <returns>UTC DateTime</returns>
        public static DateTime ToDateTimeUnixMilliseconds(this long unixTimeStampMilliseconds)
        {
            return unixEpoch.AddMilliseconds(unixTimeStampMilliseconds);
        }

        /// <summary>
        /// Get a unix timestamp in milliseconds from a DateTime - the DateTime will be converted to universal time before conversion if needed.
        /// </summary>
        /// <param name="dt">DateTime</param>
        /// <returns>Unix timestamp in milliseconds</returns>
        public static double ToUnixMilliseconds(this DateTime dt)
        {
            if (dt.Kind != DateTimeKind.Utc)
            {
                dt = dt.ToUniversalTime();
            }
            return (dt - unixEpoch).TotalMilliseconds;
        }

        /// <summary>
        /// Get a unix timestamp in milliseconds from a DateTime - the DateTime will be converted to universal time before conversion if needed.
        /// </summary>
        /// <param name="dt">DateTime</param>
        /// <returns>Unix timestamp in milliseconds</returns>
        public static long ToUnixMillisecondsLong(this DateTime dt)
        {
            if (dt.Kind != DateTimeKind.Utc)
            {
                dt = dt.ToUniversalTime();
            }
            return (long)(dt - unixEpoch).TotalMilliseconds;
        }

        /// <summary>
        /// Clean ip address - remove scope and convert to ipv4 if ipv6 mapped to ipv4
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <param name="ownsIP">Whether this ip is owned by the caller</param>
        /// <returns>Cleaned ip address</returns>
        public static System.Net.IPAddress Clean(this System.Net.IPAddress ip, bool ownsIP = false)
        {
            return ip.RemoveScopeId(ownsIP).MapToIPv4IfIPv6();
        }

        /// <summary>
        /// Check if two ip are equal, using MapToIPv6 if needed
        /// </summary>
        /// <param name="ipAddress">IP address</param>
        /// <param name="other">Other ip address</param>
        /// <returns>True if ip are equal or equal, false otherwise</returns>
        public static bool EqualsWithMapToIPv6(this System.Net.IPAddress ipAddress, System.Net.IPAddress other)
        {
            if (ipAddress.Equals(other))
            {
                return true;
            }
            try
            {
                IPAddress ipv6 = (ipAddress.IsLocalHost() ? IPAddress.Parse("::1") : ipAddress.MapToIPv6());
                IPAddress otherIPV6 = (other.IsLocalHost() ? IPAddress.Parse("::1") : other.MapToIPv6());
                return ipv6.Equals(otherIPV6);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets whether the ip address is local host
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <returns>True if localhost, false if not</returns>
        public static bool IsLocalHost(this IPAddress ip)
        {
            if (ip != null)
            {
                Span<byte> bytes = stackalloc byte[16];
                ip.TryWriteBytes(bytes, out int byteCount);

                if (byteCount == 4)
                {
                    return (bytes[0] == 127 && bytes[1] == 0 && (bytes[2] == 0 || bytes[2] == 1) && bytes[3] == 1);
                }
                else if (byteCount == 16)
                {
                    return (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
                        bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
                        bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 &&
                        bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1);
                }
            }
            return false;
        }

        /// <summary>
        /// Get a UInt32 from an ipv4 address. By default, the UInt32 will be in the byte order of the CPU.
        /// </summary>
        /// <param name="ip">IPV4 address</param>
        /// <param name="swap">Whether to make the uint in the byte order of the cpu (true and default) or network host order (false)</param>
        /// <returns>UInt32</returns>
        /// <exception cref="InvalidOperationException">Not an ipv4 address</exception>
        public static uint ToUInt32(this IPAddress ip, bool swap = true)
        {
            if (ip is null || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                throw new InvalidOperationException(ip?.ToString() + " is not an ipv4 address");
            }

            Span<byte> bytes = stackalloc byte[4];
            ip.TryWriteBytes(bytes, out int byteCount);
            if (swap && BitConverter.IsLittleEndian)
            {
                // reverse big endian (network order) to little endian
                for (int i = 0; i < byteCount / 2; i++)
                {
                    (bytes[byteCount - i - 1], bytes[i]) = (bytes[i], bytes[byteCount - i - 1]);
                }
            }
            return BitConverter.ToUInt32(bytes);
        }

        /// <summary>
        /// Get a UInt128 from an ipv6 address. By default, the UInt128 will be in the byte order of the CPU.
        /// </summary>
        /// <param name="ip">IPV6 address</param>
        /// <param name="swap">Whether to make the byte order of the cpu (true and default) or network host order (false)</param>
        /// <returns>UInt128</returns>
        /// <exception cref="InvalidOperationException">Not an ipv6 address</exception>
        public static unsafe UInt128 ToUInt128(this IPAddress ip, bool swap = true)
        {
            if (ip is null || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                throw new InvalidOperationException(ip?.ToString() + " is not an ipv6 address");
            }

            Span<byte> bytes = stackalloc byte[16];
            ip.TryWriteBytes(bytes, out int byteCount);
            if (swap && BitConverter.IsLittleEndian)
            {
                // reverse big endian (network order) to little endian
                for (int i = 0; i < byteCount / 2; i++)
                {
                    (bytes[byteCount - i - 1], bytes[i]) = (bytes[i], bytes[byteCount - i - 1]);
                }
            }
            ulong l1 = BitConverter.ToUInt64(bytes[..8]);
            ulong l2 = BitConverter.ToUInt64(bytes[8..]);
            return new UInt128(l2, l1);
        }

        /// <summary>
        /// Get a UInt128 from an ipv6 address. The UInt128 will use the raw bytes from the ip address as is.
        /// </summary>
        /// <param name="ip">IPV6 address</param>
        /// <returns>UInt128</returns>
        /// <exception cref="InvalidOperationException">Not an ipv6 address</exception>
        public static unsafe UInt128 ToUInt128Raw(this IPAddress ip)
        {
            Span<byte> bytes = stackalloc byte[16];
            ip.TryWriteBytes(bytes, out int byteCount);
            fixed (byte* ptr = bytes)
            {
                ulong* ulongPtr = (ulong*)ptr;
                return new UInt128(*ulongPtr, *(++ulongPtr));
            }
        }

        /// <summary>
        /// Increment an ip address
        /// </summary>
        /// <param name="ipAddress">Ip address to increment</param>
        /// <param name="result">Incremented ip address or null if failure</param>
        /// <returns>True if incremented, false if ip address was at max value</returns>
        public static bool TryIncrement(this IPAddress ipAddress, out IPAddress result)
        {
            Span<byte> bytes = stackalloc byte[16];
            ipAddress.TryWriteBytes(bytes, out int byteCount);

            for (int k = byteCount - 1; k >= 0; k--)
            {
                if (bytes[k] == byte.MaxValue)
                {
                    bytes[k] = 0;
                    continue;
                }
                bytes[k]++;
                result = new IPAddress(bytes[..byteCount]);
                if (result.IsIPv4MappedToIPv6 != ipAddress.IsIPv4MappedToIPv6)
                {
                    result = null;
                    return false;
                }
                return true;
            }

            // all bytes are already max values, no increment possible
            result = null;
            return false;
        }

        /// <summary>
        /// Decrement an ip address
        /// </summary>
        /// <param name="ipAddress">Ip address to decrement</param>
        /// <param name="result">Decremented ip address or null if failure</param>
        /// <returns>True if decremented, false if ip address was at min value</returns>
        public static bool TryDecrement(this IPAddress ipAddress, out IPAddress result)
        {
            Span<byte> bytes = stackalloc byte[16];
            ipAddress.TryWriteBytes(bytes, out int byteCount);

            for (int k = byteCount - 1; k >= 0; k--)
            {
                if (bytes[k] == 0)
                {
                    bytes[k] = byte.MaxValue;
                    continue;
                }
                bytes[k]--;
                result = new IPAddress(bytes[..byteCount]);
                if (result.IsIPv4MappedToIPv6 != ipAddress.IsIPv4MappedToIPv6)
                {
                    result = null;
                    return false;
                }
                return true;
            }

            // all bytes are already min values, no decrement possible
            result = null;
            return false;
        }

        /// <summary>
        /// Compare two ip address for sort order
        /// </summary>
        /// <param name="ip1">First ip address</param>
        /// <param name="ip2">Second ip address</param>
        /// <returns>CompareTo result (negative less than, 0 equal, 1 greater than)</returns>
        public static int CompareTo(this IPAddress ip1, IPAddress ip2)
        {
            if (ip1 is null)
            {
                return (ip2 is null ? 0 : -1);
            }
            else if (ip1.AddressFamily != ip2.AddressFamily)
            {
                return ip1.AddressFamily.CompareTo(ip2.AddressFamily);
            }
            else if (ip1.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                UInt32 u1 = ip1.ToUInt32();
                UInt32 u2 = ip2.ToUInt32();
                return u1.CompareTo(u2);
            }
            else
            {
                UInt128 u1 = ip1.ToUInt128();
                UInt128 u2 = ip2.ToUInt128();
                return u1.CompareToIn(u2);
            }
        }

        /// <summary>
        /// Get a firewall ip address, clean and normalize
        /// </summary>
        /// <param name="ipAddress">IP address string</param>
        /// <param name="normalizedIP">The normalized ip string, ready to go in the firewall or null if invalid ip address</param>
        /// <returns>True if ip address can go in the firewall, false otherwise</returns>
        public static bool TryNormalizeIPAddress(this string ipAddress, out string normalizedIP)
        {
            normalizedIP = (ipAddress ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalizedIP) ||
                normalizedIP == "-" ||
                normalizedIP == "0.0.0.0" ||
                normalizedIP == "127.0.0.1" ||
                normalizedIP == "::0" ||
                normalizedIP == "::1" ||
                !IPAddressRange.TryParse(normalizedIP, out IPAddressRange range))
            {
                // try parsing assuming the ip is followed by a port
                int pos = normalizedIP.LastIndexOf(':');
                if (pos >= 0)
                {
                    normalizedIP = normalizedIP[..pos];
                    if (!IPAddressRange.TryParse(normalizedIP, out range))
                    {
                        normalizedIP = null;
                        return false;
                    }
                }
                else
                {
                    normalizedIP = null;
                    return false;
                }
            }
            try
            {
                normalizedIP = (range.Single ? range.Begin.ToString() : range.ToCidrString());
            }
            catch (Exception ex)
            {
                Logger.Debug("Failed to normalize ip {0}, it is not a single ip or cidr range: {1}", ipAddress, ex);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Get an ip address from a string.
        /// </summary>
        /// <param name="value">String</param>
        /// <returns>IPAddress or null if failure</returns>
        public static IPAddress ToIPAddress(this string value)
        {
            if (IPAddress.TryParse(value, out IPAddress ip))
            {
                return ip;
            }
            return null;
        }

        /// <summary>
        /// Get an ip address from a UInt32. By default, the value is assumed to be in the byte order of the CPU.
        /// </summary>
        /// <param name="value">UInt32</param>
        /// <param name="swap">Whether to swap to network host order if needed</param>
        /// <returns>IPAddress</returns>
        public static IPAddress ToIPAddress(this uint value, bool swap = true)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (swap && BitConverter.IsLittleEndian)
            {
                bytes = bytes.Reverse().ToArray();
            }
            return new IPAddress(bytes);
        }

        /// <summary>
        /// Get an ip address from a UInt128. The UInt128 is assumed to be in the byte order of the CPU.
        /// </summary>
        /// <param name="value">UInt128</param>
        /// <returns>IPAddress</returns>
        public static IPAddress ToIPAddress(this UInt128 value)
        {
            byte[] bytes1 = BitConverter.GetBytes(value.MostSignificant);
            byte[] bytes2 = BitConverter.GetBytes(value.LeastSignificant);
            byte[] finalBytes;
            if (BitConverter.IsLittleEndian)
            {
                bytes1 = bytes1.Reverse().ToArray();
                bytes2 = bytes2.Reverse().ToArray();
                finalBytes = [.. bytes1, .. bytes2];
            }
            else
            {
                finalBytes = [.. bytes2, .. bytes1];
            }
            return new IPAddress(finalBytes);
        }

        /// <summary>
        /// Get an ip address from a UInt128. The UInt128 raw bytes are used as is.
        /// </summary>
        /// <param name="value">UInt128</param>
        /// <returns>IPAddress</returns>
        public static unsafe IPAddress ToIPAddressRaw(this UInt128 value)
        {
            byte* bytes = (byte*)&value;
            ReadOnlySpan<byte> spanBytes = new(bytes, 16);
            return new IPAddress(spanBytes);
        }

        /// <summary>
        /// Convert UnmanagedMemoryStream to a byte array
        /// </summary>
        /// <param name="stream">UnmanagedMemoryStream</param>
        /// <returns>Byte array</returns>
        public static byte[] ToArray(this UnmanagedMemoryStream stream)
        {
            byte[] bytes = new byte[stream.Length];
            stream.Position = 0;
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)stream.ReadByte();
            }
            return bytes;
        }

        /// <summary>
        /// Attempt to get string
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default if not found</param>
        /// <returns>String or null if not found</returns>
        public static string GetString(this System.Text.Json.JsonElement elem, string name, string defaultValue = null)
        {
            if (elem.ValueKind == JsonValueKind.Object && elem.TryGetProperty(name, out var elem2))
            {
                return elem2.ToString();
            }
            return defaultValue;
        }

        /// <summary>
        /// Attempt to get int32
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default value if not found</param>
        /// <returns>Int32</returns>
        public static int GetInt32(this System.Text.Json.JsonElement elem, string name, int defaultValue = 0)
        {
            int value = defaultValue;
            if (elem.ValueKind != JsonValueKind.Object || !elem.TryGetProperty(name, out var elem2))
            {
                return value;
            }
            else if (!int.TryParse(elem2.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out value))
            {
                value = defaultValue;
            }
            return value;
        }

        /// <summary>
        /// Attempt to get int64
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default value if not found</param>
        /// <returns>Int64</returns>
        public static long GetInt64(this System.Text.Json.JsonElement elem, string name, long defaultValue = 0)
        {
            long value = defaultValue;
            if (elem.ValueKind != JsonValueKind.Object || !elem.TryGetProperty(name, out var elem2))
            {
                return value;
            }
            else if (!long.TryParse(elem2.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out value))
            {
                value = defaultValue;
            }
            return value;
        }

        /// <summary>
        /// Get datetime 
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default value</param>
        /// <returns>DateTime or defaultValue if not found</returns>
        public static DateTime GetDateTime(this System.Text.Json.JsonElement elem, string name, DateTime defaultValue = default)
        {
            if (!elem.TryGetProperty(name, out var elem2) ||
                !elem2.TryGetDateTime(out DateTime timeStamp))
            {
                timeStamp = defaultValue;
            }
            return timeStamp;
        }

        /// <summary>
        /// Get bool
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default value if not found</param>
        /// <returns>Bool value or defaultValue if not found</returns>
        public static bool GetBool(this System.Text.Json.JsonElement elem, string name, bool defaultValue = false)
        {
            string boolString = elem.GetString(name);
            if (!bool.TryParse(boolString, out bool value))
            {
                value = defaultValue;
            }
            return value;
        }

        /// <summary>
        /// Parse text into Timespan
        /// </summary>
        /// <param name="text">Text</param>
        /// <returns>TimeSpan or null if failure</returns>
        public static TimeSpan? ParseTimeSpan(this string text)
        {
            if (TimeSpan.TryParse(text, CultureInfo.InvariantCulture, out var result))
            {
                return result;
            }
            return null;
        }

        /// <summary>
        /// Parse text into an int
        /// </summary>
        /// <param name="text">Text</param>
        /// <returns>int or null if failure</returns>
        public static int? ParseInt(this string text)
        {
            if (int.TryParse(text, CultureInfo.InvariantCulture, out var result))
            {
                return result;
            }
            return null;
        }

        /// <summary>
        /// Get smallest timespan
        /// </summary>
        /// <param name="t1">First TimeSpan</param>
        /// <param name="t2">Second TimeSpan</param>
        /// <param name="defaultValue">Default if both t1 and t2 are null</param>
        /// <returns>Smallest TimeSpan or defaultValue if both t1 and t2 are null</returns>
        public static TimeSpan SmallestTimeSpan(TimeSpan? t1, TimeSpan? t2, TimeSpan defaultValue)
        {
            if (t1 is null && t2 is null)
            {
                return defaultValue;
            }
            else if (t1 is null)
            {
                return t2.Value;
            }
            else if (t2 is null)
            {
                return t1.Value;
            }
            return t1.Value > t2.Value ? t2.Value : t1.Value;
        }

        /// <summary>
        /// Clamp a timespan, if out of bounds it will be clamped. If timespan is less than 1 second, it will be set to timeMax.
        /// </summary>
        /// <param name="value">Value to clamp</param>
        /// <param name="timeMin">Min value</param>
        /// <param name="timeMax">Max value</param>
        /// <returns>Clamped value or value if not clamped</returns>
        public static TimeSpan Clamp(this TimeSpan value, TimeSpan timeMin, TimeSpan timeMax)
        {
            if (value.TotalSeconds < 1.0 || value > timeMax)
            {
                value = timeMax;
            }
            else if (value < timeMin)
            {
                value = timeMin;
            }
            return value;
        }

        /// <summary>
        /// Generic clamp method. If clampTimeSpanToMax and typeof(T) is TimeSpan, any value less than 1 second will become max.
        /// </summary>
        /// <typeparam name="T">Type</typeparam>
        /// <param name="val">Value</param>
        /// <param name="min">Min value</param>
        /// <param name="max">Max value</param>
        /// <param name="clampSmallTimeSpanToMax">Whether to clamp small timespan to max value.</param>
        /// <returns>Clamped value</returns>
        public static T Clamp<T>(this T val, T min, T max, bool clampSmallTimeSpanToMax = false) where T : IComparable<T>
        {
            if (clampSmallTimeSpanToMax && typeof(T) == typeof(TimeSpan) && ((TimeSpan)(object)val).TotalSeconds < 1.0)
            {
                return (T)(object)max;
            }
            else if (val.CompareTo(min) < 0)
            {
                return min;
            }
            else if (val.CompareTo(max) > 0)
            {
                return max;
            }
            return val;
        }

        /// <summary>
        /// Deserialize an object from string json
        /// </summary>
        /// <param name="json">Json</param>
        /// <returns>Object</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static T DeserializeJson<T>(string json)
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(json, options: jsonOptions);
        }

        /// <summary>
        /// Deserialize an object from byte[] json
        /// </summary>
        /// <param name="json">Json</param>
        /// <returns>Object or default of T if exception</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static T DeserializeJson<T>(byte[] json)
        {
            try
            {
                var utf8JsonReader = new Utf8JsonReader(json);
                return System.Text.Json.JsonSerializer.Deserialize<T>(ref utf8JsonReader, jsonOptions);
            }
            catch
            {
                return default;
            }
        }

        /// <summary>
        /// Serialize an object to utf8 json
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>String json</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static string SerializeJson(this object obj)
        {
            return System.Text.Json.JsonSerializer.Serialize(obj, options: jsonOptions);
        }

        /// <summary>
        /// Serialize an object to utf8 json
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>Utf8 json</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static byte[] SerializeUtf8Json(this object obj)
        {
            return System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(obj, options: jsonOptions);
        }

        /// <summary>
        /// Serialize an object to utf8 json
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="stream">Stream</param>
        /// <returns>Utf8 json</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static void SerializeUtf8Json(this object obj, Stream stream)
        {
            System.Text.Json.JsonSerializer.Serialize(stream, obj, options: jsonOptions);
        }

        /// <summary>
        /// Get an enumerator that locks an object until enumeration is complete
        /// </summary>
        /// <typeparam name="T">Type</typeparam>
        /// <param name="obj">Object to lock during enumeration</param>
        /// <returns>Enumerator with lock, must Dispose to release lock</returns>
        public static IEnumerator<T> GetLockedEnumerator<T>(this IEnumerable<T> obj)
        {
            return new LockedEnumerable<T>(obj);
        }

#pragma warning disable CA1401

        /// <summary>
        /// Get user id on Linux
        /// </summary>
        /// <returns>Uid</returns>
        [DllImport("libc")]
        public static extern uint getuid();

#pragma warning restore CA1401

#if !IPBAN_API

        /// <summary>
        /// Throw an exception if the process is not running as administrator (Windows) or root (Linux).
        /// </summary>
        /// <exception cref="InvalidOperationException">Application is not run as administrator</exception>
        public static void RequireAdministrator()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    throw new InvalidOperationException("Application must be run as administrator");
                }
            }
            else if (getuid() != 0)
            {
                throw new InvalidOperationException("Application must be run as root");
            }
        }

#endif

        /// <summary>
        /// Delete a file with retry
        /// </summary>
        /// <param name="path">Path to delete</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        public static void FileDeleteWithRetry(string path, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            if (File.Exists(path))
            {
                Retry(() => File.Delete(path), millisecondsBetweenRetry, retryCount);
            }
        }

        /// <summary>
        /// Copy a file with retry
        /// </summary>
        /// <param name="sourceFile">Source file to move</param>
        /// <param name="destFile">Destination file to move to</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        public static void FileCopyWithRetry(string sourceFile, string destFile, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            if (File.Exists(sourceFile))
            {
                Retry(() => Directory.CreateDirectory(Path.GetDirectoryName(destFile)), millisecondsBetweenRetry, retryCount);
                Retry(() => File.Copy(sourceFile, destFile, true), millisecondsBetweenRetry, retryCount);
            }
        }

        /// <summary>
        /// Move a file with retry
        /// </summary>
        /// <param name="sourceFile">Source file to move</param>
        /// <param name="destFile">Destination file to move to</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        public static void FileMoveWithRetry(string sourceFile, string destFile, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            if (File.Exists(sourceFile))
            {
                ExtensionMethods.FileDeleteWithRetry(destFile);
                Retry(() => Directory.CreateDirectory(Path.GetDirectoryName(destFile)), millisecondsBetweenRetry, retryCount);
                Retry(() => File.Move(sourceFile, destFile), millisecondsBetweenRetry, retryCount);
            }
        }

        /// <summary>
        /// Move a directory recursively with retry. Does nothing if sourceDir does not exist.
        /// </summary>
        /// <param name="sourceDir">Source directory</param>
        /// <param name="destDir">Destination directory</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        public static void DirectoryMoveWithRetry(string sourceDir, string destDir, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            if (Directory.Exists(sourceDir))
            {
                Retry(() => Directory.Move(sourceDir, destDir), millisecondsBetweenRetry, retryCount);
            }
        }

        /// <summary>
        /// Delete directory recursively with retry for each file. Does nothing if dir does not exist.
        /// </summary>
        /// <param name="dir">Directory to delete</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        public static void DirectoryDeleteWithRetry(string dir, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            if (Directory.Exists(dir))
            {
                foreach (string file in Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories))
                {
                    FileDeleteWithRetry(file, millisecondsBetweenRetry, retryCount);
                }
                Retry(() => Directory.Delete(dir, true), millisecondsBetweenRetry, retryCount);
            }
        }

        /// <summary>
        /// Write all file text with retry
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="text">Text</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        /// <returns>Task</returns>
        public static void FileWriteAllTextWithRetry(string fileName, string text, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            string fullPath = Path.GetFullPath(fileName);
            string dirName = Path.GetDirectoryName(fullPath);
            Directory.CreateDirectory(dirName);
            Retry(() => File.WriteAllText(fileName, text, Utf8EncodingNoPrefix), millisecondsBetweenRetry, retryCount);
        }

        /// <summary>
        /// Write all file text with retry
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="text">Text</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        /// <returns>Task</returns>
        public static Task FileWriteAllTextWithRetryAsync(string fileName, string text, int millisecondsBetweenRetry = 200, int retryCount = 10)
        {
            string fullPath = Path.GetFullPath(fileName);
            string dirName = Path.GetDirectoryName(fullPath);
            Directory.CreateDirectory(dirName);
            return RetryAsync(() => File.WriteAllTextAsync(fileName, text, Utf8EncodingNoPrefix), millisecondsBetweenRetry, retryCount);
        }

        /// <summary>
        /// Attempt an action with retry and delay between failures. Throws an exception if all retry fails.
        /// </summary>
        /// <param name="action">Action</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        /// <param name="exceptionRetry">Optional func to determine if exception should be retried</param>
        public static void Retry(Action action, int millisecondsBetweenRetry = 1000, int retryCount = 3,
            Func<Exception, bool> exceptionRetry = null)
        {
            Exception lastError = null;
            for (int i = 1; i <= retryCount; i++)
            {
                try
                {
                    action();
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    if (lastError is OperationCanceledException ||
                        (exceptionRetry != null && !exceptionRetry(ex)))
                    {
                        break;
                    }
                    else if (i != retryCount)
                    {
                        Thread.Sleep(millisecondsBetweenRetry);
                    }
                }
            }
            throw lastError;
        }

        /// <summary>
        /// Attempt an action with retry and delay between failures. Throws an exception if all retry fails.
        /// </summary>
        /// <param name="action">Action</param>
        /// <param name="millisecondsBetweenRetry">Milliseconds between each retry</param>
        /// <param name="retryCount">Retry count</param>
        /// <param name="exceptionRetry">Optional func to determine if exception should be retried</param>
        /// <returns>Task</returns>
        public static async Task RetryAsync(Func<Task> action, int millisecondsBetweenRetry = 1000, int retryCount = 3,
            Func<Exception, bool> exceptionRetry = null)
        {
            Exception lastError = null;
            for (int i = 1; i <= retryCount; i++)
            {
                try
                {
                    await action();
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    if (lastError is OperationCanceledException ||
                        (exceptionRetry != null && !exceptionRetry(ex)))
                    {
                        break;
                    }
                    else if (i != retryCount)
                    {
                        Thread.Sleep(millisecondsBetweenRetry);
                    }
                }
            }
            throw lastError;
        }

        /// <summary>
        /// Check if type is an anonymous type
        /// </summary>
        /// <param name="type">Type</param>
        /// <returns>True if anonymous type, false otherwise</returns>
        public static bool IsAnonymousType(this Type type)
        {
            return (type != null && Attribute.IsDefined(type, typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), false) &&
                type.IsGenericType && type.Name.Contains("AnonymousType", StringComparison.OrdinalIgnoreCase) &&
                (type.Name.StartsWith("<>") || type.Name.StartsWith("VB$", StringComparison.OrdinalIgnoreCase)) &&
                type.Attributes.HasFlag(TypeAttributes.NotPublic));
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

        /// <summary>
        /// Make a task execute synchronously
        /// </summary>
        /// <param name="task">Task</param>
        public static void Sync(this ValueTask task)
        {
            task.ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Make a task execute synchronously
        /// </summary>
        /// <param name="task">Task</param>
        /// <returns>Result</returns>
        public static T Sync<T>(this ValueTask<T> task)
        {
            return task.ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Wait for value tasks to complete
        /// </summary>
        /// <param name="tasks">Value tasks</param>
        /// <returns>Task that finishes when all value tasks have finished</returns>
        public static Task WhenAll(this IEnumerable<ValueTask> tasks)
        {
            List<Task> valueTaskTasks = [];
            foreach (ValueTask task in tasks)
            {
                valueTaskTasks.Add(task.AsTask());
            }
            return Task.WhenAll(valueTaskTasks);
        }

        /// <summary>
        /// Wait for value tasks to complete
        /// </summary>
        /// <typeparam name="T">Type of value task</typeparam>
        /// <param name="tasks">Value tasks</param>
        /// <returns>Task that finishes when all value tasks have finished</returns>
        public static Task WhenAll<T>(this IEnumerable<ValueTask<T>> tasks)
        {
            List<Task> valueTaskTasks = [];
            foreach (ValueTask<T> task in tasks)
            {
                valueTaskTasks.Add(task.AsTask());
            }
            return Task.WhenAll(valueTaskTasks);
        }

        /// <summary>
        /// Async wait
        /// </summary>
        /// <param name="handle">Handle</param>
        /// <returns>Task</returns>
        public static Task AsTask(this WaitHandle handle)
        {
            return AsTask(handle, Timeout.InfiniteTimeSpan);
        }

        /// <summary>
        /// Async wait
        /// </summary>
        /// <param name="handle">Handle</param>
        /// <param name="timeout">Timeout</param>
        /// <returns>Task</returns>
        public static Task AsTask(this WaitHandle handle, TimeSpan timeout)
        {
            var tcs = new TaskCompletionSource<object>();
            var registration = ThreadPool.RegisterWaitForSingleObject(handle, (state, timedOut) =>
            {
                var localTcs = (TaskCompletionSource<object>)state;
                if (timedOut)
                {
                    localTcs.TrySetCanceled();
                }
                else
                {
                    localTcs.TrySetResult(null);
                }
            }, tcs, timeout, executeOnlyOnce: true);
            tcs.Task.ContinueWith((_, state) => ((RegisteredWaitHandle)state).Unregister(null), registration, TaskScheduler.Default);
            return tcs.Task;
        }

        /// <summary>
        /// Cleanup database files
        /// </summary>
        /// <param name="folder">Folder</param>
        public static void RemoveDatabaseFiles(string folder = null)
        {
            folder ??= AppContext.BaseDirectory;

            // cleanup any db, set or tbl files
            foreach (string file in Directory.GetFiles(folder, "*.set")
                .Union(Directory.GetFiles(folder, "*.tbl"))
                .Union(Directory.GetFiles(folder, "*.set6"))
                .Union(Directory.GetFiles(folder, "*.tbl6"))
                .Union(Directory.GetFiles(folder, "*.sqlite"))
                .Union(Directory.GetFiles(folder, "*.sqlite-wal"))
                .Union(Directory.GetFiles(folder, "*.sqlite-shm"))
                .Union(Directory.GetFiles(folder, "*-journal")))
            {
                ExtensionMethods.FileDeleteWithRetry(file, 1000);
            }
        }

        /// <summary>
        /// Remove the scope id from the ip address if there is a scope id
        /// </summary>
        /// <param name="ipAddress">IP address to remove scope id from</param>
        /// <param name="ownsIP">Whether this ip is owned by the caller</param>
        /// <returns>This ip address if no scope id removed, otherwise a new ip address with scope removed if ownsIP is false, or the same ip
        /// with scope removed if ownsIP is true</returns>
        private static IPAddress RemoveScopeId(this IPAddress ipAddress, bool ownsIP = false)
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (ownsIP)
                {
                    ipAddress.ScopeId = 0;
                }
                else
                {
                    Span<byte> bytes = stackalloc byte[16];
                    ipAddress.TryWriteBytes(bytes, out int byteCount);
                    return new IPAddress(bytes[..byteCount]);
                }
            }
            return ipAddress;
        }

        /// <summary>
        /// Map ip address to ipv4 if it is an ipv6 address mapped to ipv4
        /// </summary>
        /// <param name="ip">IP address</param>
        /// <returns>IP address mapped to ipv4 if mapped to ipv4 in ipv6 format</returns>
        private static System.Net.IPAddress MapToIPv4IfIPv6(this System.Net.IPAddress ip)
        {
            if (ip is null)
            {
                return ip;
            }
            else if (ip.IsIPv4MappedToIPv6)
            {
                return ip.MapToIPv4();
            }
            return ip;
        }

        /// <summary>
        /// Remove internal ip address ranges from the specified range
        /// </summary>
        /// <param name="range">IP address range</param>
        /// <returns>IP address ranges without any internal ip address ranges, will just contain range if no internal ip
        /// addresses are in range</returns>
        public static IEnumerable<IPAddressRange> RemoveInternalRanges(this IPAddressRange range)
        {
            List<IPAddressRange> results = [];
            var internalRanges = (range.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? NetworkUtility.InternalRangesIPV4 : NetworkUtility.InternalRangesIPV6);
            foreach (var internalRange in internalRanges)
            {
                // internal ranges are sorted so we can make assumptions that the left most non intersecting part of range is good
                if (range.Chomp(internalRange, out IPAddressRange left, out IPAddressRange right))
                {
                    if (right is null)
                    {
                        range = left;

                        // all done!
                        break;
                    }
                    else if (left is null)
                    {
                        // proceed with reduced range
                        range = right;
                    }
                    else
                    {
                        // left result is sanitized of internal ips, still need to sanitize the right
                        results.Add(left);
                        range = right;
                    }
                }
            }
            if (range is not null)
            {
                results.Add(range);
            }
            return results;
        }

        /// <summary>
        /// Combine IPAddressRange instances that are consecutive, ranges are assumed to be sorted
        /// </summary>
        /// <param name="ranges">Ranges</param>
        /// <returns>Combined ranges</returns>
        public static IEnumerable<IPAddressRange> Combine(this IEnumerable<IPAddressRange> ranges)
        {
            using var e = ranges.GetEnumerator();
            IPAddressRange current = null;
            IPAddressRange next;
            if (e.MoveNext())
            {
                current = e.Current;
            }
            while (e.MoveNext())
            {
                next = e.Current;
                if (current.TryCombine(next, out IPAddressRange combined))
                {
                    current = combined;
                }
                else
                {
                    yield return current;
                    current = next;
                }
            }
            if (current is not null)
            {
                yield return current;
            }
        }

        /// <summary>
        /// Invert ip address ranges, the result is ranges that are every other ip address range except the provided ranges.
        /// Ranges must be sorted with duplicates removed
        /// </summary>
        /// <param name="ranges">Ranges</param>
        /// <returns>Inverted ip address ranges, in sorted order and combined where needed</returns>
        public static IEnumerable<IPAddressRange> Invert(this IEnumerable<IPAddressRange> ranges)
        {
            static IEnumerable<IPAddressRange> ProcessRanges(IEnumerable<IPAddressRange> _ranges,
                System.Net.IPAddress startPrev,
                System.Net.IPAddress lastPrev,
                System.Net.Sockets.AddressFamily addressFamily)
            {
                IPAddressRange leftGap = null;
                System.Net.IPAddress endPrev = null;
                foreach (var range in Combine(_ranges.Where(r => r.Begin.AddressFamily == addressFamily)
                    .SelectMany(r => r.RemoveInternalRanges())))
                {
                    // left gap
                    if (range.Begin.TryDecrement(out endPrev) &&
                        startPrev.IsIPv4MappedToIPv6 == endPrev.IsIPv4MappedToIPv6)
                    {
                        leftGap = new IPAddressRange(startPrev, endPrev);
                        foreach (var scrubbedIP in RemoveInternalRanges(leftGap))
                        {
                            yield return scrubbedIP;
                        }
                    }

                    // if more gap on right keep going
                    if (!range.End.TryIncrement(out startPrev) ||
                        startPrev.IsIPv4MappedToIPv6 != range.End.IsIPv4MappedToIPv6)
                    {
                        startPrev = null;
                        break;
                    }
                }

                // last range
                if (leftGap is not null && startPrev is not null)
                {
                    leftGap = new IPAddressRange(startPrev, lastPrev);
                    foreach (var scrubbedIP in RemoveInternalRanges(leftGap))
                    {
                        yield return scrubbedIP;
                    }
                }
            }

            {
                var ipv4Ranges = ProcessRanges(ranges, NetworkUtility.FirstIPV4, NetworkUtility.LastIPV4, System.Net.Sockets.AddressFamily.InterNetwork);
                foreach (var range in Combine(ipv4Ranges))
                {
                    yield return range;
                }
            }
            {
                var ipv6Ranges = ProcessRanges(ranges, NetworkUtility.FirstIPV6, NetworkUtility.LastIPV6, System.Net.Sockets.AddressFamily.InterNetworkV6);
                foreach (var range in Combine(ipv6Ranges))
                {
                    yield return range;
                }
            }
        }

        /// <summary>
        /// Normalize string for query
        /// </summary>
        /// <param name="s">String</param>
        /// <returns>Normalized string</returns>
        public static string NormalizeForQuery(this string s)
        {
            if (s is null)
            {
                return s;
            }
            s = s.Normalize(NormalizationForm.FormD);
            StringBuilder result = new();
            bool lastWasSpace = true;
            foreach (char c in s)
            {
                switch (char.GetUnicodeCategory(c))
                {
                    case System.Globalization.UnicodeCategory.DecimalDigitNumber:
                    case System.Globalization.UnicodeCategory.LetterNumber:
                    case System.Globalization.UnicodeCategory.LowercaseLetter:
                    case System.Globalization.UnicodeCategory.OtherLetter:
                    case System.Globalization.UnicodeCategory.OtherNumber:
                    case System.Globalization.UnicodeCategory.TitlecaseLetter:
                    case System.Globalization.UnicodeCategory.UppercaseLetter:
                        result.Append(char.ToLowerInvariant(c));
                        lastWasSpace = false;
                        break;

                    default:
                        if (!lastWasSpace)
                        {
                            result.Append(' ');
                            lastWasSpace = true;
                        }
                        break;
                }
            }

            // trim end spaces without making more garbage
            while (result.Length > 0 && result[^1] == ' ')
            {
                result.Length--;
            }

            return result.ToString();
        }

        /// <summary>
        /// Get all entries from sorted list that match a prefix
        /// </summary>
        /// <typeparam name="TValue">Type of value</typeparam>
        /// <param name="sortedList">Sorted list</param>
        /// <param name="prefix">Prefix to query, does not need to be normalized</param>
        /// <returns>All matching entries</returns>
        public static IEnumerable<KeyValuePair<string, TValue>> GetEntriesMatchingPrefix<TValue>(this SortedList<string, TValue> sortedList, string prefix)
        {
            int lower = 0;
            int upper = sortedList.Count - 1;
            int middle;
            int compare;
            prefix = NormalizeForQuery(prefix);

            // Perform binary search to find the first occurrence of the prefix
            while (lower <= upper)
            {
                middle = lower + (upper - lower) / 2;
                compare = string.Compare(prefix, sortedList.Keys[middle], true);
                if (compare == 0)
                {
                    lower = middle;
                    break;
                }
                else if (compare < 0)
                {
                    // Move upper down to find the first match
                    upper = middle - 1;
                }
                else
                {
                    lower = middle + 1;
                }
            }

            // Iterate forward from the found index
            for (int i = lower; i < sortedList.Count && sortedList.Keys[i].StartsWith(prefix, StringComparison.OrdinalIgnoreCase); i++)
            {
                var kv = new KeyValuePair<string, TValue>(sortedList.Keys[i], sortedList.Values[i]);
                yield return kv;
            }
        }
    }
}
