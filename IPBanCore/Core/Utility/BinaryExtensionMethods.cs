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
using System.IO;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// BinaryWriter and BinaryReader extension methods
    /// </summary>
    public static class BinaryExtensionMethods
    {
        /// <summary>
        /// Write 7 bit encoded int
        /// </summary>
        /// <param name="writer">BinaryWriter</param>
        /// <param name="value">Value</param>
        public static void Write7BitEncodedInt32(this BinaryWriter writer, int value)
        {
            // Write out an Int32 7 bits at a time.  The high bit of the byte,
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
        /// Write 7 bit encoded long
        /// </summary>
        /// <param name="writer">BinaryWriter</param>
        /// <param name="value">Value</param>
        public static void Write7BitEncodedInt64(this BinaryWriter writer, long value)
        {
            // Write out an Int64 7 bits at a time.  The high bit of the byte,
            // when on, tells reader to continue reading more bytes.
            ulong v = (ulong)value;   // support negative numbers
            while (v >= 0x80)
            {
                writer.Write((byte)(v | 0x80));
                v >>= 7;
            }
            writer.Write((byte)v);
        }

        /// <summary>
        /// Read 7 bit encoded long
        /// </summary>
        /// <param name="reader">BinaryReader</param>
        /// <returns>Value</returns>
        public static long Read7BitEncodedInt64(this BinaryReader reader)
        {
            // Read out an Int64 7 bits at a time.  The high bit
            // of the byte when on means to continue reading more bytes.
            long count = 0;
            int shift = 0;
            byte b;
            do
            {
                // Check for a corrupted stream.  Read a max of 10 bytes.
                // In a future version, add a DataFormatException.
                if (shift == 10 * 7)  // 10 bytes max per Int64 shift += 7
                    throw new FormatException();

                // ReadByte handles end of stream cases for us.
                b = reader.ReadByte();
                count |= ((long)(b & 0x7F) << shift);
                shift += 7;
            } while ((b & 0x80) != 0);
            return count;
        }
    }
}
