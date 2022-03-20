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
using System.Collections;
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
        private static readonly System.Net.IPAddress[] localHostIP = new System.Net.IPAddress[] { System.Net.IPAddress.Parse("127.0.0.1"), System.Net.IPAddress.Parse("::1") };

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
        /// Throw ArgumentNullException if obj is null
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="name">Parameter name</param>
        /// <param name="message">Message</param>
        public static void ThrowIfNullOrEmpty(this string obj, string name = null, string message = null)
        {
            if (obj is null)
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
            using var hasher = SHA256.Create();
            return BitConverter.ToString(hasher.ComputeHash(Encoding.UTF8.GetBytes(s))).Replace("-", string.Empty);
        }

        /// <summary>
        /// Convert bytes to hex string
        /// </summary>
        /// <param name="bytes">Bytes</param>
        /// <returns>Hex string</returns>
        public static string ToHexString(this byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
        }

        /// <summary>
        /// Convert hex string to bytes
        /// </summary>
        /// <param name="s">String in hex format</param>
        /// <returns>Bytes</returns>
        public static byte[] ToBytesFromHex(this string s)
        {
            byte[] bytes = new byte[s.Length / 2];
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
        /// <param name="unixTimeStampSeconds">Unix epoch in milliseconds</param>
        /// <returns>UTC DateTime</returns>
        public static DateTime ToDateTimeUnixMilliseconds(this double unixTimeStampMilliseconds)
        {
            return unixEpoch.AddMilliseconds(unixTimeStampMilliseconds);
        }

        /// <summary>
        /// Get a UTC date time from a unix epoch in milliseconds
        /// </summary>
        /// <param name="unixTimeStampSeconds">Unix epoch in milliseconds</param>
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
        /// An extension method to determine if an IP address is internal, as specified in RFC1918
        /// </summary>
        /// <param name="ip">The IP address that will be tested</param>
        /// <returns>Returns true if the IP is internal, false if it is external</returns>
        public static bool IsInternal(this System.Net.IPAddress ip)
        {
            try
            {
                ip = ip.Clean();
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Span<byte> bytes = stackalloc byte[4];
                    if (!ip.TryWriteBytes(bytes, out int byteCount))
                    {
                        return true;
                    }
                    return bytes[0] switch
                    {
                        10 or 127 => true,
                        172 => bytes[1] >= 16 && bytes[1] < 32,
                        192 => bytes[1] == 168,
                        0 => true,
                        _ => false,
                    };
                }

                string addressAsString = ip.ToString();

                // equivalent of 127.0.0.1 in IPv6
                if (string.IsNullOrWhiteSpace(addressAsString) ||
                    addressAsString.Length < 3 ||
                    addressAsString == "::1")
                {
                    return true;
                }

                // The original IPv6 Site Local addresses (fec0::/10) are deprecated. Unfortunately IsIPv6SiteLocal only checks for the original deprecated version:
                else if (ip.IsIPv6SiteLocal)
                {
                    return true;
                }

                string firstWord = addressAsString.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries)[0];

                // These days Unique Local Addresses (ULA) are used in place of Site Local. 
                // ULA has two variants: 
                //      fc00::/8 is not defined yet, but might be used in the future for internal-use addresses that are registered in a central place (ULA Central). 
                //      fd00::/8 is in use and does not have to registered anywhere.
                if (firstWord.Length >= 4 && firstWord[..2] == "fc")
                {
                    return true;
                }
                else if (firstWord.Length >= 4 && firstWord[..2] == "fd")
                {
                    return true;
                }
                // Link local addresses (prefixed with fe80) are not routable
                else if (firstWord == "fe80")
                {
                    return true;
                }
                // Discard Prefix
                else if (firstWord == "100")
                {
                    return true;
                }

                // Any other IP address is not Unique Local Address (ULA)
                return false;
            }
            catch (Exception ex)
            {
                Logger.Warn("Invalid ip isinternal check: {0}, {1}", ip, ex);
                return true;
            }
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
        /// <param name="swap">Whether to make the uint in the byte order of the cpu (true) or network host order (false)</param>
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
        /// Get a UInt128 from an ipv6 address. The UInt128 will be in the byte order of the CPU.
        /// </summary>
        /// <param name="ip">IPV6 address</param>
        /// <param name="swap">Whether to make the byte order of the cpu (true) or network host order (false)</param>
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
                finalBytes = bytes1.Concat(bytes2).ToArray();
            }
            else
            {
                finalBytes = bytes2.Concat(bytes1).ToArray();
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
            byte[] managedBytes = new byte[16];
            for (int i = 0; i < managedBytes.Length; i++)
            {
                managedBytes[i] = bytes[i];
            }
            return new IPAddress(managedBytes);
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
        /// <returns>String or null if not found</returns>
        public static string GetString(this System.Text.Json.JsonElement elem, string name)
        {
            if (elem.TryGetProperty(name, out var elem2))
            {
                return elem2.ToString();
            }
            return null;
        }

        /// <summary>
        /// Attempt to get int32
        /// </summary>
        /// <param name="elem">Element</param>
        /// <param name="name">Property name</param>
        /// <param name="defaultValue">Default value if not found</param>
        /// <returns></returns>
        public static int GetInt32(this System.Text.Json.JsonElement elem, string name, int defaultValue = 0)
        {
            if (!elem.TryGetProperty(name, out var elem2) ||
                !int.TryParse(elem2.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out var value))
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

        private static Assembly[] allAssemblies;

        /// <summary>
        /// Get all assemblies, including referenced assemblies. This method will be cached beyond the first call.
        /// </summary>
        /// <returns>All referenced assemblies</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static IReadOnlyCollection<Assembly> GetAllAssemblies()
        {
            if (allAssemblies != null)
            {
                return allAssemblies;
            }

            var allAssembliesHashSet = new HashSet<Assembly>();
            foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies().ToArray())
            {
                allAssembliesHashSet.Add(assembly);
                AssemblyName[] references = assembly.GetReferencedAssemblies();
                foreach (AssemblyName reference in references)
                {
                    try
                    {
                        Assembly referenceAssembly = Assembly.Load(reference);
                        allAssembliesHashSet.Add(referenceAssembly);
                    }
                    catch
                    {
                        // don't care, if the assembly can't be loaded there's nothing more to be done
                    }
                }
            }

            // get referenced assemblies does not include every assembly if no code was referenced from that assembly
            string path = AppContext.BaseDirectory;
            string[] appFiles = Directory.GetFiles(path);
            string pluginPath = Path.Combine(path, "plugins");
            if (Directory.Exists(pluginPath))
            {
                string[] pluginFiles = Directory.GetFiles(pluginPath);
                appFiles = appFiles.Concat(pluginFiles).ToArray();
            }
            foreach (string dllFile in appFiles.Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    bool exists = false;
                    foreach (Assembly assembly in allAssembliesHashSet)
                    {
                        try
                        {
                            exists = assembly.Location.Equals(dllFile, StringComparison.OrdinalIgnoreCase);
                            if (exists)
                            {
                                break;
                            }
                        }
                        catch
                        {
                            // some assemblies will throw upon attempt to access Location property...
                        }
                    }
                    if (!exists)
                    {
                        allAssembliesHashSet.Add(Assembly.LoadFrom(dllFile));
                    }
                }
                catch
                {
                    // nothing to be done
                }
            }
            return allAssemblies = allAssembliesHashSet.ToArray();
        }

        private static Type[] allTypes;

        /// <summary>
        /// Get all types from all assemblies
        /// </summary>
        /// <returns>List of all types</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static IReadOnlyCollection<Type> GetAllTypes()
        {
            if (allTypes != null)
            {
                return allTypes;
            }
            IReadOnlyCollection<Assembly> assemblies = GetAllAssemblies();
            List<Type> types = new();

            // prefix to entry assembly first pattern to greatly reduce ram usage
            string prefix = Assembly.GetEntryAssembly()?.GetName().Name ?? string.Empty;
            int pos = prefix.IndexOf('.');
            if (pos >= 0)
            {
                pos++;
                prefix = prefix[..pos];
            }

            // no filter if running unit tests
            if (UnitTestDetector.Running)
            {
                prefix = null;
            }

            foreach (Assembly assembly in assemblies.Where(a => a.FullName is null ||
                string.IsNullOrWhiteSpace(prefix) ||
                a.FullName.StartsWith(prefix)))
            {
                try
                {
                    // some assemblys throw in unit tests in VS 2019, bug in MSFT...
                    types.AddRange(assembly.GetTypes());
                }
                catch
                {
                    // ignore
                }
            }
            return allTypes = types.ToArray();
        }

        /// <summary>
        /// Get the ip addresses of the local machine
        /// </summary>
        /// <param name="dns">Dns lookup</param>
        /// <param name="allowLocal">Whether to return localhost ip</param>
        /// <param name="addressFamily">Desired address family or null for all</param>
        /// <returns>Local ip address or empty array if unable to determine. If no address family match, falls back to an ipv6 attempt.</returns>
        public static async Task<System.Net.IPAddress[]> GetLocalIPAddressesAsync(this IDnsLookup dns,
            bool allowLocal = true, System.Net.Sockets.AddressFamily? addressFamily = null)
        {
            try
            {
                // append ipv4 first, then the ipv6 then the remote ip
                List<IPAddress> ips = new();
                string hostName = await dns.GetHostNameAsync();
                IPAddress[] hostAddresses = await dns.GetHostAddressesAsync(hostName);
                ips.AddRange(hostAddresses.Where(i => !i.IsLocalHost()));

                // sort ipv4 first
                ips.Sort((ip1, ip2) =>
                {
                    int compare = ip1.AddressFamily.CompareTo(ip2.AddressFamily);
                    if (compare == 0)
                    {
                        compare = ip1.CompareTo(ip2);
                    }
                    return compare;
                });

                if (allowLocal)
                {
                    ips.AddRange(localHostIP);
                }

                return ips.Where(ip => (allowLocal || !ip.IsLocalHost()) &&
                    (addressFamily is null || ip.AddressFamily == addressFamily.Value)).ToArray();
            }
            catch
            {
                // eat exception, delicious
            }
            return Array.Empty<IPAddress>();
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
        /// Get a System.Type from a string, searching loaded and referenced assemblies if needed
        /// </summary>
        /// <param name="typeString"></param>
        /// <returns>System.Type or null if none found</returns>
        [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "jjxtra")]
        public static Type GetTypeFromString(string typeString)
        {
            Type type = Type.GetType(typeString);
            if (type != null)
            {
                return type;
            }

            IReadOnlyCollection<Assembly> assemblies = GetAllAssemblies();
            foreach (Assembly assembly in assemblies)
            {
                type = assembly.GetType(typeString);
                if (type != null)
                {
                    return type;
                }
            }
            return null;
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
        /// <typeparam name="T">Type of value task</typeparam>
        /// <param name="tasks">Value tasks</param>
        /// <returns>Task that finishes when all value tasks have finished</returns>
        public static Task WhenAll(this IEnumerable<ValueTask> tasks)
        {
            List<Task> valueTaskTasks = new();
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
            List<Task> valueTaskTasks = new();
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
    }
}
