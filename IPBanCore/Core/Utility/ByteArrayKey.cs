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
    /// Allows using byte array as a key
    /// </summary>
    public struct ByteArrayKey
    {
        /// <summary>
        /// Bytes
        /// </summary>
        public byte[] Bytes { get; private set; }

        private readonly int _hashCode;

        private static int GetHashCode(Span<byte> bytes)
        {
            unchecked
            {
                int hash = 17;
                foreach (byte element in bytes)
                {
                    hash = hash * 31 + element;
                }
                return hash;
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bytes">Bytes</param>
        public ByteArrayKey(byte[] bytes)
        {
            Bytes = bytes;
            _hashCode = GetHashCode(bytes);
        }

        /// <summary>
        /// Check if equal to other byte array key
        /// </summary>
        /// <param name="obj">Other byte array key</param>
        /// <returns>True if equal, false otherwise</returns>
        public override bool Equals(object obj)
        {
            var other = (ByteArrayKey)obj;
            return Bytes.AsSpan().SequenceEqual(other.Bytes.AsSpan());
        }

        /// <summary>
        /// Get hash code for the bytes
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return _hashCode;
        }
    }
}
