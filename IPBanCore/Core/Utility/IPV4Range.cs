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

using System;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Range of ipv4 addresses
    /// </summary>
    public readonly struct IPV4Range : IComparable<IPV4Range>
    {
        /// <summary>
        /// Begin ip
        /// </summary>
        public readonly uint Begin;

        /// <summary>
        /// End ip
        /// </summary>
        public readonly uint End;

        /// <summary>
        /// Get hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                return (int)(Begin + End);
            }
        }

        /// <summary>
        /// Check for equality
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>True if equal, false otherwise</returns>

        public override bool Equals(object obj)
        {
            if (obj is not IPV4Range range)
            {
                return false;
            }
            return Begin == range.Begin && End == range.End;
        }

        /// <summary>
        /// Equals
        /// </summary>
        /// <param name="r1">Range1</param>
        /// <param name="r2">Range2</param>
        /// <returns>True if equal</returns>
        public static bool operator ==(IPV4Range r1, IPV4Range r2)
        {
            return r1.Equals(r2);
        }

        /// <summary>
        /// Not equals
        /// </summary>
        /// <param name="r1">Range1</param>
        /// <param name="r2">Range2</param>
        /// <returns>True if not equal</returns>
        public static bool operator !=(IPV4Range r1, IPV4Range r2)
        {
            return !r1.Equals(r2);
        }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return $"{Begin.ToIPAddress()}/{End.ToIPAddress()}";
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="range">IPAddressRange</param>
        /// <exception cref="InvalidOperationException">Invalid address family</exception>
        public IPV4Range(IPAddressRange range)
        {
            if (range.Begin.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                throw new InvalidOperationException("Wrong address family for an ipv4 range");
            }
            Begin = range.Begin.ToUInt32();
            End = range.End.ToUInt32();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="begin">Begin</param>
        /// <param name="end">End</param>
        public IPV4Range(uint begin, uint end)
        {
            Begin = begin;
            End = end;
        }

        /// <summary>
        /// Convert to an ip address range
        /// </summary>
        /// <returns>IPAddressRange</returns>
        public IPAddressRange ToIPAddressRange() => new(Begin.ToIPAddress(), End.ToIPAddress(), true);

        /// <summary>
        /// IComparer against another IPV4Range
        /// </summary>
        /// <param name="other">Other range</param>
        /// <returns></returns>
        public int CompareTo(IPV4Range other)
        {
            int cmp = End.CompareTo(other.Begin);
            if (cmp < 0)
            {
                return cmp;
            }
            cmp = Begin.CompareTo(other.End);
            if (cmp > 0)
            {
                return cmp;
            }

            // inside range
            return 0;
        }
    }
}
