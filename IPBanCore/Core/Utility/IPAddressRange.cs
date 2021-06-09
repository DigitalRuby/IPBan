//
// derived from https://github.com/jsakamoto/ipaddressrange/blob/master/IPAddressRange/IPAddressRange.cs
// which as of March 2019 was using mozilla public license
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Represents a consecutive range of ip addresses
    /// </summary>
    public class IPAddressRange : IEnumerable<IPAddress>, IReadOnlyDictionary<string, string>, IComparable<IPAddressRange>
    {
        public static class Bits
        {
            public static bool ValidateSubnetMaskIsLinear(byte[] maskBytes, string ipRangeString, bool throwException)
            {
                var f = maskBytes[0] & 0x80; // 0x00: The bit should be 0, 0x80: The bit should be 1
                for (var i = 0; i < maskBytes.Length; i++)
                {
                    var maskByte = maskBytes[i];
                    for (var b = 0; b < 8; b++)
                    {
                        var bit = maskByte & 0x80;
                        switch (f)
                        {
                            case 0x00:
                                if (bit != 0x00)
                                {
                                    if (throwException)
                                    {
                                        throw new FormatException("The subnet mask is not linear: " + ipRangeString);
                                    }
                                    return false;
                                }
                                break;
                            case 0x80:
                                if (bit == 0x00) f = 0x00;
                                break;
                            default:
                            {
                                if (throwException)
                                {
                                    throw new FormatException("The subnet mask is not linear, bad bit: " + ipRangeString);
                                }
                                return false;
                            }
                        }
                        maskByte <<= 1;
                    }
                }
                return true;
            }
            public static byte[] Not(byte[] bytes)
            {
                var result = (byte[])bytes.Clone();
                for (var i = 0; i < result.Length; i++)
                {
                    result[i] = (byte)~result[i];
                }
                return result;
                //return bytes.Select(b => (byte)~b).ToArray();
            }

            public static byte[] And(byte[] A, byte[] B)
            {
                var result = (byte[])A.Clone();
                for (var i = 0; i < A.Length; i++)
                {
                    result[i] &= B[i];
                }
                return result;
                //return A.Zip(B, (a, b) => (byte)(a & b)).ToArray();
            }

            public static byte[] Or(byte[] A, byte[] B)
            {
                var result = (byte[])A.Clone();
                for (var i = 0; i < A.Length; i++)
                {
                    result[i] |= B[i];
                }
                return result;
                //return A.Zip(B, (a, b) => (byte)(a | b)).ToArray();
            }

            // DON'T FIX this non-intuitive behavior that returns true when A <= B, 
            // even if the method name means "A is Greater than or Equals B", for keeping backward compatibility.
            // Fixed verison is in "NetTools.Internal" namespace "Bits" class.
            [EditorBrowsable(EditorBrowsableState.Never), Obsolete("This method returns true when A<=B, not A is greater than or equal (>=) B. use LtE method to check A<=B or not.")]
            public static bool GE(byte[] A, byte[] B) => LtE(A, B);

            // DON'T FIX this non-intuitive behavior that returns true when A >= B, 
            // even if the method name means "A is Less than or Equals B", for keeping backward compatibility.
            // Fixed verison is in "NetTools.Internal" namespace "Bits" class.
            [EditorBrowsable(EditorBrowsableState.Never), Obsolete("This method returns true when A>=B, not A is less than or equal (<=) B. use GtE method to check A>=B or not.")]
            public static bool LE(byte[] A, byte[] B) => GtE(A, B);

            public static bool LtE(byte[] A, byte[] B, int offset = 0)
            {
                if (A is null) throw new ArgumentNullException(nameof(A));
                if (B is null) throw new ArgumentNullException(nameof(B));
                if (offset < 0) throw new ArgumentException("offset must be greater than or equal 0.", nameof(offset));
                if (A.Length <= offset || B.Length <= offset) throw new ArgumentException("offset must be less than length of A and B.", nameof(offset));

                return LtECore(A, B, offset);
            }

            internal static bool LtECore(byte[] A, byte[] B, int offset = 0)
            {
                var length = A.Length;
                if (length > B.Length) length = B.Length;
                for (var i = offset; i < length; i++)
                {
                    if (A[i] != B[i]) return A[i] <= B[i];
                }
                return true;
            }

            public static bool GtE(byte[] A, byte[] B, int offset = 0)
            {
                if (A is null) throw new ArgumentNullException(nameof(A));
                if (B is null) throw new ArgumentNullException(nameof(B));
                if (offset < 0) throw new ArgumentException("offset must be greater than or equal 0.", nameof(offset));
                if (A.Length <= offset || B.Length <= offset) throw new ArgumentException("offset must be less than length of A and B.", nameof(offset));

                return GtECore(A, B, offset);
            }

            internal static bool GtECore(byte[] A, byte[] B, int offset = 0)
            {
                var length = A.Length;
                if (length > B.Length) length = B.Length;
                for (var i = offset; i < length; i++)
                {
                    if (A[i] != B[i]) return A[i] >= B[i];
                }
                return true;
            }

            public static bool IsEqual(byte[] A, byte[] B)
            {
                if (A is null || B is null) { return false; }
                if (A.Length != B.Length) { return false; }
                return A.Zip(B, (a, b) => a == b).All(x => x == true);
            }

            public static byte[] GetBitMask(int sizeOfBuff, int bitLen)
            {
                var maskBytes = new byte[sizeOfBuff];
                var bytesLen = bitLen / 8;
                var bitsLen = bitLen % 8;
                for (var i = 0; i < bytesLen; i++)
                {
                    maskBytes[i] = 0xff;
                }
                if (bitsLen > 0) maskBytes[bytesLen] = (byte)~Enumerable.Range(1, 8 - bitsLen).Select(n => 1 << n - 1).Aggregate((a, b) => a | b);
                return maskBytes;
            }

            /// <summary>
            /// Counts the number of leading 1's in a bitmask.
            /// Returns null if value is invalid as a bitmask.
            /// </summary>
            /// <param name="bytes"></param>
            /// <returns></returns>
            public static int? GetBitMaskLength(byte[] bytes)
            {
                if (bytes is null) throw new ArgumentNullException(nameof(bytes));

                var bitLength = 0;
                var idx = 0;

                // find beginning 0xFF
                for (; idx < bytes.Length && bytes[idx] == 0xff; idx++) ;
                bitLength = 8 * idx;

                if (idx < bytes.Length)
                {
                    switch (bytes[idx])
                    {
                        case 0xFE: bitLength += 7; break;
                        case 0xFC: bitLength += 6; break;
                        case 0xF8: bitLength += 5; break;
                        case 0xF0: bitLength += 4; break;
                        case 0xE0: bitLength += 3; break;
                        case 0xC0: bitLength += 2; break;
                        case 0x80: bitLength += 1; break;
                        case 0x00: break;
                        default: // invalid bitmask
                            return null;
                    }
                    // remainder must be 0x00
                    if (bytes.Skip(idx + 1).Any(x => x != 0x00)) return null;
                }
                return bitLength;
            }
        }

        // Pattern 1. CIDR range: "192.168.0.0/24", "fe80::%lo0/10"
        private static readonly Regex m1_regex = new(@"^(?<adr>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))[ \t]*/[ \t]*(?<maskLen>\d+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pattern 2. Uni address: "127.0.0.1", "::1%eth0"
        private static readonly Regex m2_regex = new(@"^(?<adr>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pattern 3. Begin end range: "169.254.0.0-169.254.0.255", "fe80::1%23-fe80::ff%23"
        //            also shortcut notation: "192.168.1.1-7" (IPv4 only)
        private static readonly Regex m3_regex = new(@"^(?<begin>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))[ \t]*[\-–][ \t]*(?<end>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pattern 4. Bit mask range: "192.168.0.0/255.255.255.0"
        private static readonly Regex m4_regex = new(@"^(?<adr>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))[ \t]*/[ \t]*(?<bitmask>[\da-f\.:]+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Begin ip address
        /// </summary>
        public IPAddress Begin { get; }

        /// <summary>
        /// End ip address
        /// </summary>
        public IPAddress End { get; }

        /// <summary>
        /// Gets whether this is a single ip address
        /// </summary>
        public bool Single { get; }

        /// <summary>
        /// Creates an empty range object, equivalent to "0.0.0.0/0".
        /// </summary>
        public IPAddressRange() : this(new IPAddress(0L)) { Single = true; }

        /// <summary>
        /// Creates a new range with the same start/end address (range of one)
        /// </summary>
        /// <param name="singleAddress">Single ip address</param>
        /// <param name="ownsIP">Whether this instance owns the ip object</param>
        public IPAddressRange(IPAddress singleAddress, bool ownsIP = false)
        {
            singleAddress.ThrowIfNull(nameof(singleAddress));
            Begin = End = singleAddress.Clean();
            Single = true;
        }

        /// <summary>
        /// Create a new range from a begin and end address.
        /// Throws an exception if Begin comes after End, or the
        /// addresses are not in the same family.
        /// </summary>
        /// <param name="begin">Start ip address</param>
        /// <param name="end">End ip address</param>
        /// <param name="ownsIP">Whether this instance owns the start and end ip objects</param>
        public IPAddressRange(IPAddress begin, IPAddress end, bool ownsIP = false)
        {
            begin.ThrowIfNull(nameof(begin));
            end.ThrowIfNull(nameof(end));
            begin = begin.Clean(ownsIP);
            end = end.Clean(ownsIP);
            if (begin.AddressFamily != end.AddressFamily)
            {
                throw new ArgumentException("Begin ip and end ip must be of the same address family", nameof(end));
            }
            else if (begin.CompareTo(end) > 0)
            {
                throw new ArgumentException("Begin ip address must be less than or equal the end ip address", nameof(begin));
            }
            Begin = begin;
            End = end;
            Single = Begin.Equals(End);
        }

        /// <summary>
        /// Creates a range from a base address and mask bits.
        /// This can also be used with <see cref="SubnetMaskLength"/> to create a
        /// range based on a subnet mask.
        /// </summary>
        /// <param name="baseAddress"></param>
        /// <param name="maskLength"></param>
        public IPAddressRange(IPAddress baseAddress, int maskLength)
        {
            baseAddress.ThrowIfNull(nameof(baseAddress));
            baseAddress = baseAddress.Clean();
            var baseAdrBytes = baseAddress.GetAddressBytes();
            if (baseAdrBytes.Length * 8 < maskLength)
            {
                throw new FormatException("Invalid mask length " + maskLength + " for ip " + baseAddress);
            }
            var maskBytes = Bits.GetBitMask(baseAdrBytes.Length, maskLength);
            baseAdrBytes = Bits.And(baseAdrBytes, maskBytes);
            Begin = new IPAddress(baseAdrBytes);
            End = new IPAddress(Bits.Or(baseAdrBytes, Bits.Not(maskBytes)));
            Single = Begin.Equals(End);
        }

        /// <summary>
        /// Check if this ip address range contains an ip address
        /// </summary>
        /// <param name="ipAddress">The ip address to check for</param>
        /// <returns>True if ipaddress is in this range, false otherwise</returns>
        public bool Contains(IPAddress ipAddress)
        {
            ipAddress.ThrowIfNull(nameof(ipAddress));
            ipAddress = ipAddress.Clean();
            if (ipAddress.AddressFamily != Begin.AddressFamily)
            {
                return false;
            }
            return (Begin.CompareTo(ipAddress) <= 0 && End.CompareTo(ipAddress) >= 0);
        }

        /// <summary>
        /// Check if an ip range is contained in this ip range
        /// </summary>
        /// <param name="range">IP range</param>
        /// <returns>True if range is contained in this ip range, false otherwise</returns>
        public bool Contains(IPAddressRange range)
        {
            range.ThrowIfNull(nameof(range));
            if (Begin.AddressFamily != range.Begin.AddressFamily)
            {
                return false;
            }
            return (Begin.CompareTo(range.Begin) <= 0 && End.CompareTo(range.End) >= 0);
        }

        /// <summary>
        /// Parse ip address
        /// </summary>
        /// <param name="ipRangeString">IP range string</param>
        /// <param name="throwException">True to throw exception if failure, false to return null</param>
        /// <returns>IPAddress range or null if failure and throwException is false</returns>
        public static IPAddressRange Parse(string ipRangeString, bool throwException = true)
        {
            try
            {
                if (throwException)
                {
                    ipRangeString.ThrowIfNull(nameof(ipRangeString));
                }
                else if (ipRangeString is null)
                {
                    return null;
                }

                // trim white spaces.
                ipRangeString = ipRangeString.Trim();

                // Pattern 1. CIDR range: "192.168.0.0/24", "fe80::/10%eth0"
                var m1 = m1_regex.Match(ipRangeString);
                if (m1.Success)
                {
                    var baseAdrBytes = IPAddress.Parse(m1.Groups["adr"].Value).GetAddressBytes();
                    var maskLen = int.Parse(m1.Groups["maskLen"].Value);
                    if (baseAdrBytes.Length * 8 < maskLen)
                    {
                        if (throwException)
                        {
                            throw new FormatException("Invalid mask length for " + ipRangeString);
                        }
                        return null;
                    }
                    var maskBytes = Bits.GetBitMask(baseAdrBytes.Length, maskLen);
                    baseAdrBytes = Bits.And(baseAdrBytes, maskBytes);
                    return new IPAddressRange(new IPAddress(baseAdrBytes), new IPAddress(Bits.Or(baseAdrBytes, Bits.Not(maskBytes))), true);
                }

                // Pattern 2. Uni address: "127.0.0.1", ":;1"
                var m2 = m2_regex.Match(ipRangeString);
                if (m2.Success)
                {
                    return new IPAddressRange(IPAddress.Parse(ipRangeString), true);
                }

                // Pattern 3. Begin end range: "169.254.0.0-169.254.0.255"
                var m3 = m3_regex.Match(ipRangeString);
                if (m3.Success)
                {
                    // if the left part contains dot, but the right one does not, we treat it as a shortuct notation
                    // and simply copy the part before last dot from the left part as the prefix to the right one
                    var begin = m3.Groups["begin"].Value;
                    var end = m3.Groups["end"].Value;
                    if (begin.Contains('.') && !end.Contains('.'))
                    {
                        if (end.Contains('%'))
                        {
                            if (throwException)
                            {
                                throw new FormatException("The end of IPv4 range shortcut notation contains scope id: " + ipRangeString);
                            }
                            return null;
                        }
                        var lastDotAt = begin.LastIndexOf('.');
                        end = begin.Substring(0, lastDotAt + 1) + end;
                    }

                    return new IPAddressRange(IPAddress.Parse(begin), IPAddress.Parse(end), true);
                }

                // Pattern 4. Bit mask range: "192.168.0.0/255.255.255.0"
                var m4 = m4_regex.Match(ipRangeString);
                if (m4.Success)
                {
                    var baseAdrBytes = IPAddress.Parse(m4.Groups["adr"].Value).GetAddressBytes();
                    var maskBytes = IPAddress.Parse(m4.Groups["bitmask"].Value).GetAddressBytes();
                    if (!Bits.ValidateSubnetMaskIsLinear(maskBytes, ipRangeString, throwException))
                    {
                        return null;
                    }
                    baseAdrBytes = Bits.And(baseAdrBytes, maskBytes);
                    return new IPAddressRange(new IPAddress(baseAdrBytes), new IPAddress(Bits.Or(baseAdrBytes, Bits.Not(maskBytes))), true);
                }

                if (throwException)
                {
                    throw new FormatException("Unknown IP range string: " + ipRangeString);
                }
            }
            catch
            {
                if (throwException)
                {
                    throw;
                }
            }
            return null;
        }


        /// <summary>
        /// Try to parse an ip range string
        /// </summary>
        /// <param name="ipRangeString">IP range string</param>
        /// <param name="ipRange">Parsed ip range or null if failure to parse</param>
        /// <returns>True if ip range string is parsed successfully, false otherwise</returns>
        public static bool TryParse(string ipRangeString, out IPAddressRange ipRange)
        {
            return (ipRange = IPAddressRange.Parse(ipRangeString, false)) is not null;
        }

        /// <summary>
        /// Return a combined ip address range of all ip addresses if all ip addresses are consecutive
        /// </summary>
        /// <param name="ips">IP addresses</param>
        /// <returns>IPAddressRange or null if ip addresses are not consecutive</returns>
        public static IPAddressRange TryCreateFromIPAddresses(params IPAddress[] ips)
        {
            return TryCreateFromIPAddressRanges(ips.Select(i => new IPAddressRange(i)).ToArray());
        }

        /// <summary>
        /// Return a combined ip address range of all ranges if all ranges are consecutive
        /// </summary>
        /// <param name="ranges">IP address ranges</param>
        /// <returns>IPAddressRange or null if ip address ranges are not consecutive</returns>
        public static IPAddressRange TryCreateFromIPAddressRanges(params IPAddressRange[] ranges)
        {
            IPAddressRange first = null;
            IPAddressRange current = null;
            foreach (IPAddressRange range in ranges.OrderBy(i => i))
            {
                if (first is null)
                {
                    first = range;
                }
                if (current is null)
                {
                    current = range;
                }
                else if (!current.End.TryIncrement(out IPAddress incrementedIp) || !incrementedIp.Equals(range.Begin))
                {
                    return null;
                }
                current = range;
            }
            if (first is null || current is null)
            {
                return null;
            }
            return new IPAddressRange(first.Begin, current.End);
        }

        /// <summary>
        /// Convert ip address range to string implicit
        /// </summary>
        /// <param name="range">Ip address range</param>
        public static implicit operator string(IPAddressRange range)
        {
            return range.ToString();
        }

        /// <summary>
        /// Convert ip address range to string implicit
        /// </summary>
        /// <param name="s">Ip address range string or null if failure to parse</param>
        public static implicit operator IPAddressRange(string s)
        {
            return (string.IsNullOrWhiteSpace(s) ? null : IPAddressRange.Parse(s));
        }

        /// <summary>
        /// Convert ip address range to string implicit
        /// </summary>
        /// <param name="ip">Ip address string or null if ip is null</param>
        public static implicit operator IPAddressRange(IPAddress ip)
        {
            return (ip is null ? null : new IPAddressRange(ip));
        }

        /// <summary>
        /// Takes a subnetmask (eg, "255.255.254.0") and returns the CIDR bit length of that
        /// address. Throws an exception if the passed address is not valid as a subnet mask.
        /// </summary>
        /// <param name="subnetMask">The subnet mask to use</param>
        /// <returns></returns>
        public static int SubnetMaskLength(IPAddress subnetMask)
        {
            subnetMask.ThrowIfNull(nameof(subnetMask));
            var length = Bits.GetBitMaskLength(subnetMask.GetAddressBytes());
            length.ThrowArgumentExceptionIfNull<int?>(nameof(subnetMask), "Not a valid subnet mask");
            return length.Value;
        }

        /// <summary>
        /// Enumerate all ip addresses in this ip address range
        /// </summary>
        /// <returns>Enumerator of all ip addresses in this ip address range</returns>
        public IEnumerator<IPAddress> GetEnumerator()
        {
            var first = Begin;
            var last = End;
            var current = first;
            while (true)
            {
                yield return current;
                if (current.Equals(last) || !current.TryIncrement(out current))
                {
                    break;
                }
            }
        }

        /// <inheritdoc />
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Returns the range in the format "begin-end", or as a single address if End is the same as Begin.
        /// </summary>
        /// <param name="separator">Separator</param>
        /// <returns>String</returns>
        public string ToString(char separator)
        {
            return Equals(Begin, End) ? Begin.ToString() : string.Format("{0}{1}{2}", Begin, separator, End);
        }

        /// <summary>
        /// Returns the range as a string
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return ToCidrString(false);
        }

        /// <summary>
        /// Check if this ip address range equals another object
        /// </summary>
        /// <param name="obj">Other object</param>
        /// <returns>True if equal, false otherwise</returns>
        public override bool Equals(object obj)
        {
            if (obj is null || obj is not IPAddressRange other)
            {
                return false;
            }
            return Begin.Equals(other.Begin) && End.Equals(other.End);
        }

        /// <summary>
        /// Get a hash code for this ip address range
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return (Begin is null ? 0 : Begin.GetHashCode()) + (End is null ? 0 : End.GetHashCode());
        }

        /// <summary>
        /// Get prefix / cidr mask length
        /// </summary>
        /// <param name="throwException">True to throw exception if not a cidr subnet, false to return -1</param>
        /// <returns>Prefix / cidr mask length or -1 if not a cidr subnet and throwException is false</returns>
        public int GetPrefixLength(bool throwException = true)
        {
            byte[] byteBegin = Begin.GetAddressBytes();

            // Handle single IP
            if (Single)
            {
                return byteBegin.Length * 8;
            }

            int length = byteBegin.Length * 8;
            for (int i = 0; i < length; i++)
            {
                byte[] mask = Bits.GetBitMask(byteBegin.Length, i);
                if (new IPAddress(Bits.And(byteBegin, mask)).Equals(Begin) &&
                    new IPAddress(Bits.Or(byteBegin, Bits.Not(mask))).Equals(End))
                {
                    return i;
                }
            }
            if (throwException)
            {
                throw new FormatException(string.Format("{0} is not a CIDR Subnet", ToString('-')));
            }
            return -1;
        }

        /// <summary>
        /// Returns a Cidr String if this matches exactly a Cidr subnet, otherwise a range string.
        /// </summary>
        /// <param name="displaySingleSubnet">Whether to display the cidr string even if this is a single ip address.</param>
        public string ToCidrString(bool displaySingleSubnet = true)
        {
            if (displaySingleSubnet || !Single)
            {
                int prefixLength = GetPrefixLength(false);
                if (prefixLength >= 0)
                {
                    return Begin.ToString() + "/" + prefixLength.ToString(CultureInfo.InvariantCulture);
                }
                else
                {
                    return ToString('-');
                }
            }
            return Begin.ToString();
        }

        #region JSON.NET Support by implement IReadOnlyDictionary<string, string>

        /// <summary>
        /// Constructor from enumerable of string ips
        /// </summary>
        /// <param name="items">String ips</param>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IPAddressRange(IEnumerable<KeyValuePair<string, string>> items)
        {
            this.Begin = IPAddress.Parse(TryGetValue(items, nameof(Begin), out var value1) ? value1 : throw new KeyNotFoundException());
            this.End = IPAddress.Parse(TryGetValue(items, nameof(End), out var value2) ? value2 : throw new KeyNotFoundException());
            Single = Begin.Equals(End);
        }

        /// <summary>
        /// Returns the input typed as IEnumerable&lt;IPAddress&gt;
        /// </summary>
        public IEnumerable<IPAddress> AsEnumerable() => (this as IEnumerable<IPAddress>);

        private IEnumerable<KeyValuePair<string, string>> GetDictionaryItems()
        {
            return new[] {
                new KeyValuePair<string,string>(nameof(Begin), Begin.ToString()),
                new KeyValuePair<string,string>(nameof(End), End.ToString()),
            };
        }

        private bool TryGetValue(string key, out string value) => TryGetValue(GetDictionaryItems(), key, out value);

        private bool TryGetValue(IEnumerable<KeyValuePair<string, string>> items, string key, out string value)
        {
            items ??= GetDictionaryItems();
            var foundItem = items.FirstOrDefault(item => item.Key == key);
            value = foundItem.Value;
            return foundItem.Key != null;
        }

        /// <inheritdoc />
        IEnumerable<string> IReadOnlyDictionary<string, string>.Keys => GetDictionaryItems().Select(item => item.Key);

        /// <inheritdoc />
        IEnumerable<string> IReadOnlyDictionary<string, string>.Values => GetDictionaryItems().Select(item => item.Value);

        /// <inheritdoc />
        int IReadOnlyCollection<KeyValuePair<string, string>>.Count => GetDictionaryItems().Count();

        /// <inheritdoc />
        string IReadOnlyDictionary<string, string>.this[string key] => TryGetValue(key, out var value) ? value : throw new KeyNotFoundException();

        /// <inheritdoc />
        bool IReadOnlyDictionary<string, string>.ContainsKey(string key) => GetDictionaryItems().Any(item => item.Key == key);

        /// <inheritdoc />
        bool IReadOnlyDictionary<string, string>.TryGetValue(string key, out string value) => TryGetValue(key, out value);

        /// <inheritdoc />
        IEnumerator<KeyValuePair<string, string>> IEnumerable<KeyValuePair<string, string>>.GetEnumerator() => GetDictionaryItems().GetEnumerator();

        /// <summary>
        /// Compare to another ip address range
        /// </summary>
        /// <param name="other">Other ip address range</param>
        /// <returns>CompareTo result</returns>
        public int CompareTo(IPAddressRange other)
        {
            // compare begin addresses first
            int compare = Begin.CompareTo(other.Begin);
            if (compare != 0)
            {
                return compare;
            }

            // begin address are equal, compare end addresses
            compare = End.CompareTo(other.End);
            if (compare != 0)
            {
                return compare;
            }

            return 0; // equal
        }

        #endregion
    }
}
