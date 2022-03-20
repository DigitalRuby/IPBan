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
using System.Globalization;
using System.Numerics;
using System.Runtime.InteropServices;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// A 128 bit unsigned integer.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UInt128 : IComparable<UInt128>, IEquatable<UInt128>, IFormattable
    {
        /// <summary>
        /// The number of bytes this type will take.
        /// </summary>
        public const int SizeOf = 16;

        /// <summary>
        /// The minimum UInt128 value.
        /// </summary>
        public static readonly UInt128 MinValue = 0;

        /// <summary>
        /// The maximum value of this type.
        /// </summary>
        public static readonly UInt128 MaxValue = new(ulong.MaxValue, ulong.MaxValue);

        /// <summary>
        /// A Zero UInt128 value.
        /// </summary>
        public static readonly UInt128 Zero = 0;

        /// <summary>
        /// A One UInt128 value.
        /// </summary>
        public static readonly UInt128 One = 1;

        /// <summary>
        /// Creates a value using two 64 bit values.
        /// </summary>
        /// <param name="mostSignificant">The most significant 64 bits of the value.</param>
        /// <param name="leastSignificant">The least significant 64 bits of the value.</param>
        public UInt128(ulong mostSignificant, ulong leastSignificant)
        {
            MostSignificant = mostSignificant;
            LeastSignificant = leastSignificant;
        }

        /// <summary>
        /// Conversion of a <see cref="BigInteger"/> object to an unsigned 128-bit integer value.
        /// </summary>
        /// <param name="value">The value to convert to an unsigned 128-bit integer.</param>
        /// <exception cref="OverflowException">The <paramref name="value"/> parameter represents a number less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>.</exception>
        public UInt128(BigInteger value)
            : this((ulong)(value >> 64), (ulong)(value & ulong.MaxValue))
        {
        }

        /// <summary>
        /// Defines an explicit conversion of a <see cref="BigInteger"/> object to an unsigned 128-bit integer value.
        /// </summary>
        /// <param name="value">The value to convert to an unsigned 128-bit integer.</param>
        /// <returns>The 128 bit value created by equivalent to <paramref name="value"/>.</returns>
        /// <exception cref="OverflowException">The <paramref name="value"/> parameter represents a number less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>.</exception>
        public static explicit operator UInt128(BigInteger value)
        {
            return new UInt128(value);
        }

        /// <summary>
        /// Converts the 128 bits unsigned integer to a <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="value">The 128 bit value to convert.</param>
        /// <returns>The <see cref="BigInteger"/> value converted from the 128 bit value.</returns>
        public static implicit operator BigInteger(in UInt128 value)
        {
            return value.ToBigInteger();
        }

        /// <summary>
        /// Converts a 64 bit unsigned integer to a 128 bit unsigned integer by taking all the 64 bits.
        /// </summary>
        /// <param name="value">The 64 bit value to convert.</param>
        /// <returns>The 128 bit value created by taking all the 64 bits of the 64 bit value.</returns>
        public static implicit operator UInt128(ulong value)
        {
            return new UInt128(0, value);
        }

        /// <summary>
        /// Converts the 128 bits unsigned integer to a 64 bits unsigned integer.
        /// </summary>
        /// <param name="value">The 128 bit value to convert.</param>
        /// <returns>The 64 bit value converted from the 128 bit value.</returns>
        public static explicit operator ulong(in UInt128 value)
        {
            return value.LeastSignificant;
        }

        /// <summary>
        /// Converts the string representation of a number in a specified style and culture-specific format to its <see cref="UInt128"/> equivalent.
        /// </summary>
        /// <param name="value">A string that contains a number to convert.</param>
        /// <param name="style">
        /// A bitwise combination of the enumeration values that specify the permitted format of value.
        /// </param>
        /// <param name="provider">An object that provides culture-specific formatting information about <paramref name="value"/>.</param>
        /// <returns>A value that is equivalent to the number specified in the value parameter.</returns>
        /// <exception cref="ArgumentException"><paramref name="style"/> is not a <see cref="NumberStyles"/> value or <paramref name="style"/> includes the <see cref="NumberStyles.AllowHexSpecifier"/> or <see cref="NumberStyles.HexNumber"/> flag along with another value.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
        /// <exception cref="FormatException"><paramref name="value"/> does not comply with the input pattern specified by <paramref name="style"/>.</exception>
        /// <exception cref="OverflowException">The <paramref name="value"/> parameter represents a number less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>.</exception>
        /// <remarks>
        /// The <paramref name="style"/> parameter defines the style elements 
        /// (such as white space, the positive or negative sign symbol, the group separator symbol, or the decimal point symbol) 
        /// that are allowed in the <paramref name="value"/> parameter for the parse operation to succeed. 
        /// <paramref name="style"/> must be a combination of bit flags from the <see cref="NumberStyles"/> enumeration. 
        /// The <paramref name="style"/> parameter makes this method overload useful when <paramref name="value"/> contains the string representation of a hexadecimal value, 
        /// when the number system (decimal or hexadecimal) represented by value is known only at run time, or when you want to disallow white space or a sign symbol in value.
        /// <para>Depending on the value of <paramref name="style"/>, the <paramref name="value"/> parameter may include the following elements:</para>
        /// <para>[ws][$][sign][digits,]digits[.fractional_digits][E[sign]exponential_digits][ws]</para>
        /// <para>If <paramref name="style"/> includes <see cref="NumberStyles.AllowHexSpecifier"/>, the <paramref name="value"/> parameter may include the following elements:</para>
        /// <para>[ws]hexdigits[ws]</para>
        /// <para>Elements in square brackets ([ and ]) are optional. The following table describes each element.</para>
        ///   <list type="table">
        ///     <listheader>
        ///       <term>Element</term>
        ///       <description>Description</description>
        ///     </listheader>
        ///     <item>
        ///       <term>ws</term>
        ///       <description>
        ///       Optional white space. 
        ///       White space can appear at the start of value if <paramref name="style"/> includes the <see cref="NumberStyles.AllowLeadingWhite"/> flag, 
        ///       and it can appear at the end of value if <paramref name="style"/> includes the <see cref="NumberStyles.AllowTrailingWhite"/> flag.
        ///       </description>
        ///     </item>
        ///     <item>
        ///       <term>$</term>
        ///       <description>
        ///       A culture-specific currency symbol. 
        ///       Its position in the string is defined by the <see cref="NumberFormatInfo.CurrencyNegativePattern"/> and <see cref="NumberFormatInfo.CurrencyPositivePattern"/> properties of the culture indicated by the <paramref name="provider"/> parameter. 
        ///       The current culture's currency symbol can appear in value if <paramref name="style"/> includes the <see cref="NumberStyles.AllowCurrencySymbol"/> flag.
        ///       </description>
        ///     </item>
        ///     <item>
        ///       <term>sign</term>
        ///       <description>
        ///       An optional sign. 
        ///       The sign can appear at the start of <paramref name="value"/> if <paramref name="style"/> includes the <see cref="NumberStyles.AllowLeadingSign"/> flag, 
        ///       and it can appear at the end of <paramref name="value"/> if <paramref name="style"/> includes the <see cref="NumberStyles.AllowTrailingSign"/> flag. 
        ///       Parentheses can be used in <paramref name="value"/> to indicate a negative value if <paramref name="style"/> includes the <see cref="NumberStyles.AllowParentheses"/> flag. 
        ///       </description>
        ///     </item>
        ///     <item>
        ///       <term>digits, fractional_digits, exponential_digits</term>
        ///       <description>A sequence of digits from 0 through 9. A sequence of digits from 0 through 9. For fractional_digits, only the digit 0 is valid.</description>
        ///     </item>
        ///     <item>
        ///       <term>,</term>
        ///       <description>
        ///       A culture-specific group separator symbol. 
        ///       The group separator symbol of the culture specified by <paramref name="provider"/> can appear in <paramref name="value"/> if <paramref name="style"/> includes the <see cref="NumberStyles.AllowThousands"/> flag.
        ///       </description>
        ///     </item>
        ///     <item>
        ///       <term>.</term>
        ///       <description>
        ///       A culture-specific decimal point symbol. 
        ///       The decimal point symbol of the culture designated by <paramref name="provider"/> can appear in <paramref name="value"/> if <paramref name="style"/> includes the <see cref="NumberStyles.AllowDecimalPoint"/> flag. 
        ///       Only the digit 0 can appear as a fractional digit for the parse operation to succeed; 
        ///       if fractional_digits includes any other digit, a <see cref="FormatException"/> is thrown.
        ///       </description>
        ///     </item>
        ///     <item>
        ///       <term>E</term>
        ///       <description>
        ///       The "e" or "E" character, which indicates that the value is represented in exponential (scientific) notation. 
        ///       The <paramref name="value"/> parameter can represent a number in exponential notation if <paramref name="style"/> includes the <see cref="NumberStyles.AllowExponent"/> flag.
        ///       </description>
        ///     </item>
        ///     <item>
        ///       <term>hexdigits</term>
        ///       <description>A sequence of hexadecimal digits from 0 through f, or 0 through F.</description>
        ///     </item>
        ///   </list>
        /// If you use the <see cref="Parse(string, NumberStyles, IFormatProvider)"/> method to round-trip the string representation of a <see cref="UInt128"/> value that was output by the <see cref="ToString(string, IFormatProvider)"/> method, 
        /// you should use the <see cref="ToString(string, IFormatProvider)"/> method with the "R" format specifier to generate the string representation of the <see cref="UInt128"/> value. 
        /// Otherwise, the string representation of the <see cref="UInt128"/> preserves only the 50 most significant digits of the original value, and data may be lost when you use the <see cref="Parse(string, NumberStyles, IFormatProvider)"/>  method to restore the <see cref="UInt128"/> value.
        /// <note>
        /// Unlike the other <see cref="NumberStyles"/> values, which allow for but do not require the presence of particular style elements in <paramref name="value"/>, 
        /// the <see cref="NumberStyles.AllowHexSpecifier"/> style value means that the individual numeric characters in <paramref name="value"/> are always interpreted as hexadecimal characters. 
        /// Valid hexadecimal characters are 0-9, A-F, and a-f. 
        /// The only other flags that can be combined with the <paramref name="style"/> parameter are <see cref="NumberStyles.AllowLeadingWhite"/> and <see cref="NumberStyles.AllowTrailingWhite"/>. 
        /// (The <see cref="NumberStyles"/> enumeration includes a composite number style, <see cref="NumberStyles.HexNumber"/>, that includes both white-space flags.)
        /// </note>
        /// <note>
        /// If <paramref name="value"/> is the string representation of a hexadecimal number, it cannot be preceded by any decoration (such as 0x or &amp;h) that differentiates it as a hexadecimal number. 
        /// This causes the conversion to fail.
        /// </note>
        /// If <paramref name="value"/> is a hexadecimal string, the <see cref="Parse(String, NumberStyles, IFormatProvider)"/> method interprets <paramref name="value"/> as a negative number stored by using two's complement representation if its first two hexadecimal digits are greater than or equal to 0x80. 
        /// In other words, the method interprets the highest-order bit of the first byte in <paramref name="value"/> as the sign bit. 
        /// To make sure that a hexadecimal string is correctly interpreted as a positive number, the first digit in <paramref name="value"/> must have a value of zero. 
        /// For example, the method interprets 0x80 as a negative value, but it interprets either 0x080 or 0x0080 as a positive value. 
        /// <para>
        /// The <paramref name="provider"/> parameter is an <see cref="IFormatProvider"/> implementation. 
        /// Its <see cref="IFormatProvider.GetFormat"/> method returns a <see cref="NumberFormatInfo"/> object that provides culture-specific information about the format of value. 
        /// Typically, <paramref name="provider"/> can be any one of the following: 
        /// <list type="bullet">
        ///   <item>
        ///   A <see cref="CultureInfo"/> object that represents the culture that provides numeric formatting information. 
        ///   Its <see cref="CultureInfo.GetFormat"/> method returns the <see cref="NumberFormatInfo"/> object that provides numeric formatting information.
        ///   </item>
        ///   <item>A <see cref="NumberFormatInfo"/> object that provides formatting information. (Its implementation of <see cref="NumberFormatInfo.GetFormat"/> just returns itself.)</item>
        ///   <item>
        ///   A custom object that implements <see cref="IFormatProvider"/> and uses the <see cref="IFormatProvider.GetFormat"/> method 
        ///   to instantiate and return the <see cref="NumberFormatInfo"/> object that provides formatting information.
        ///   </item>
        /// </list>
        /// If <paramref name="provider"/> is <see langword="null"/>, the <see cref="NumberFormatInfo"/> object for the current culture is used.
        /// </para>
        /// </remarks>
        public static UInt128 Parse(string value, NumberStyles style, IFormatProvider provider)
        {
            if (value is null)
                throw new ArgumentNullException(nameof(value));
            if ((style & NumberStyles.HexNumber) == NumberStyles.HexNumber)
                value = "0" + value;
            BigInteger bigIntegerValue = BigInteger.Parse(value, style, provider);
            if (bigIntegerValue < 0 || bigIntegerValue > MaxValue)
                throw new OverflowException("Value was either too large or too small for an UInt128.");

            return (UInt128)bigIntegerValue;
        }

        /// <summary>
        /// Converts the string representation of a number in a specified culture-specific format to its <see cref="UInt128"/> equivalent.
        /// Uses <see cref="NumberStyles.Integer"/> style.
        /// </summary>
        /// <param name="value">A string that contains a number to convert.</param>
        /// <param name="provider">An object that provides culture-specific formatting information about <paramref name="value"/>.</param>
        /// <returns>A value that is equivalent to the number specified in the value parameter.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
        /// <exception cref="OverflowException">The <paramref name="value"/> parameter represents a number less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>.</exception>
        /// <remarks>
        /// See important remarks in <see cref="Parse(string, NumberStyles, IFormatProvider)"/>
        /// </remarks>
        public static UInt128 Parse(string value, IFormatProvider provider)
        {
            return Parse(value, NumberStyles.Integer, provider);
        }

        /// <summary>
        /// Converts the string representation of a number in a specified style to its <see cref="UInt128"/> equivalent.
        /// Uses <see cref="CultureInfo.CurrentCulture"/> as the format provider.
        /// </summary>
        /// <param name="value">A string that contains a number to convert.</param>
        /// <param name="style"> A bitwise combination of the enumeration values that specify the permitted format of value.</param>
        /// <returns>A value that is equivalent to the number specified in the value parameter.</returns>
        /// <exception cref="ArgumentException"><paramref name="style"/> is not a <see cref="NumberStyles"/> value or <paramref name="style"/> includes the <see cref="NumberStyles.AllowHexSpecifier"/> or <see cref="NumberStyles.HexNumber"/> flag along with another value.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
        /// <exception cref="FormatException"><paramref name="value"/> does not comply with the input pattern specified by <paramref name="style"/>.</exception>
        /// <exception cref="OverflowException">The <paramref name="value"/> parameter represents a number less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>.</exception>
        /// <remarks>
        /// See important remarks in <see cref="Parse(string, NumberStyles, IFormatProvider)"/>
        /// </remarks>
        public static UInt128 Parse(string value, NumberStyles style)
        {
            return Parse(value, style, CultureInfo.CurrentCulture);
        }

        /// <summary>
        /// Converts the string representation of a number in a specified style to its <see cref="UInt128"/> equivalent.
        /// Uses <see cref="NumberStyles.Integer"/> style.
        /// Uses <see cref="CultureInfo.CurrentCulture"/> as the format provider.
        /// </summary>
        /// <param name="value">A string that contains a number to convert.</param>
        /// <returns>A value that is equivalent to the number specified in the value parameter.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
        /// <exception cref="OverflowException">The <paramref name="value"/> parameter represents a number less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>.</exception>
        /// <remarks>
        /// See important remarks in <see cref="Parse(string, NumberStyles, IFormatProvider)"/>
        /// </remarks>
        public static UInt128 Parse(string value)
        {
            return Parse(value, NumberStyles.Integer, CultureInfo.CurrentCulture);
        }

        /// <summary>
        /// Tries to convert the string representation of a number in a specified style and culture-specific format to its <see cref="UInt128"/> equivalent, 
        /// and returns a value that indicates whether the conversion succeeded.
        /// </summary>
        /// <param name="value">The string representation of a number. The string is interpreted using the style specified by <paramref name="style"/>.</param>
        /// <param name="style">
        /// A bitwise combination of enumeration values that indicates the style elements that can be present in <paramref name="value"/>. 
        /// A typical value to specify is <see cref="NumberStyles.Integer"/>.
        /// </param>
        /// <param name="provider">An object that supplies culture-specific formatting information about <paramref name="value"/>.</param>
        /// <param name="result">
        /// When this method returns, contains the <see cref="UInt128"/> equivalent to the number that is contained in value, or <see cref="UInt128.Zero"/> if the conversion failed. 
        /// The conversion fails if the value parameter is <see langword="null"/>, is not in a format that is compliant with <paramref name="style"/> or represents a number that is less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>. 
        /// This parameter is passed uninitialized.</param>
        /// <returns>true if the <paramref name="value"/> parameter was converted successfully; otherwise, false.</returns>
        /// <remarks>
        /// The <see cref="TryParse(string, NumberStyles, IFormatProvider, out UInt128)"/> method is like the <see cref="Parse(string, NumberStyles, IFormatProvider)"/> method, 
        /// except that it does not throw an exception if the conversion fails. 
        /// This method eliminates the need to use exception handling to test for a <see cref="FormatException"/> if <paramref name="value"/> is invalid and cannot be parsed successfully.
        /// <para>For more information see <see cref="Parse(string, NumberStyles, IFormatProvider)"/></para>
        /// </remarks>
        public static bool TryParse(string value, NumberStyles style, IFormatProvider provider, out UInt128 result)
        {
            bool success = BigInteger.TryParse(value, style, provider, out BigInteger bigIntegerValue);
            if (success && (bigIntegerValue < 0 || bigIntegerValue > MaxValue))
            {
                result = Zero;
                return false;
            }
            result = (UInt128)bigIntegerValue;
            return success;
        }

        /// <summary>
        /// Tries to convert the string representation of a number to its <see cref="UInt128"/> equivalent, 
        /// and returns a value that indicates whether the conversion succeeded.
        /// </summary>
        /// <param name="value">The string representation of a number.</param>
        /// <param name="result">
        /// When this method returns, contains the <see cref="UInt128"/> equivalent to the number that is contained in value, or <see cref="UInt128.Zero"/> if the conversion failed. 
        /// The conversion fails if the value parameter is <see langword="null"/> or represents a number that is less than <see cref="UInt128.MinValue"/> or greater than <see cref="UInt128.MaxValue"/>. 
        /// This parameter is passed uninitialized.</param>
        /// <returns>true if the <paramref name="value"/> parameter was converted successfully; otherwise, false.</returns>
        /// <remarks>
        /// The <see cref="TryParse(string, out UInt128)"/> method is like the <see cref="Parse(string)"/> method, 
        /// except that it does not throw an exception if the conversion fails. 
        /// This method eliminates the need to use exception handling to test for a <see cref="FormatException"/> if <paramref name="value"/> is invalid and cannot be parsed successfully.
        /// <para>For more information see <see cref="Parse(string, NumberStyles, IFormatProvider)"/></para>
        /// </remarks>
        public static bool TryParse(string value, out UInt128 result)
        {
            return TryParse(value, NumberStyles.Integer, CultureInfo.CurrentCulture, out result);
        }

        /// <summary>
        /// Returns true iff the two values represent the same value.
        /// </summary>
        /// <param name="other">The value to compare to.</param>
        /// <returns>True iff the two values represent the same value.</returns>
        public bool Equals(UInt128 other)
        {
            return MostSignificant == other.MostSignificant &&
                   LeastSignificant == other.LeastSignificant;
        }

        /// <summary>
        /// Returns true iff the two values represent the same value. With in operator.
        /// </summary>
        /// <param name="other">The value to compare to.</param>
        /// <returns>True iff the two values represent the same value.</returns>
        public bool EqualsIn(in UInt128 other)
        {
            return MostSignificant == other.MostSignificant &&
                   LeastSignificant == other.LeastSignificant;
        }

        /// <summary>
        /// Indicates whether this instance and a specified object are equal.
        /// </summary>
        /// <returns>
        /// true if <paramref name="obj"/> and this instance are the same type and represent the same value; otherwise, false.
        /// </returns>
        /// <param name="obj">Another object to compare to. </param><filterpriority>2</filterpriority>
        public override bool Equals(object obj)
        {
            return (obj is UInt128 @int) && EqualsIn(@int);
        }

        /// <summary>
        /// Compares the current object with another object of the same type.
        /// </summary>
        /// <returns>
        /// A value that indicates the relative order of the objects being compared.
        /// The return value has the following meanings:
        /// Less than zero - This object is less than the <paramref name="other"/>.
        /// parameter.Zero - This object is equal to <paramref name="other"/>.
        /// Greater than zero - This object is greater than <paramref name="other"/>. 
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public int CompareTo(UInt128 other)
        {
            if (MostSignificant != other.MostSignificant)
                return MostSignificant.CompareTo(other.MostSignificant);
            return LeastSignificant.CompareTo(other.LeastSignificant);
        }

        /// <summary>
        /// Compares the current object with another object of the same type. With in keyword
        /// </summary>
        /// <returns>
        /// A value that indicates the relative order of the objects being compared.
        /// The return value has the following meanings:
        /// Less than zero - This object is less than the <paramref name="other"/>.
        /// parameter.Zero - This object is equal to <paramref name="other"/>.
        /// Greater than zero - This object is greater than <paramref name="other"/>. 
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public int CompareToIn(in UInt128 other)
        {
            if (MostSignificant != other.MostSignificant)
                return MostSignificant.CompareTo(other.MostSignificant);
            return LeastSignificant.CompareTo(other.LeastSignificant);
        }

        /// <summary>
        /// Returns true iff the two values represent the same value.
        /// </summary>
        /// <param name="value1">The first value to compare.</param>
        /// <param name="value2">The second value to compare.</param>
        /// <returns>True iff the two values represent the same value.</returns>
        public static bool operator ==(in UInt128 value1, in UInt128 value2)
        {
            return value1.Equals(value2);
        }

        /// <summary>
        /// Returns true iff the two values represent different values.
        /// </summary>
        /// <param name="value1">The first value to compare.</param>
        /// <param name="value2">The second value to compare.</param>
        /// <returns>True iff the two values represent different values.</returns>
        public static bool operator !=(in UInt128 value1, in UInt128 value2)
        {
            return !(value1 == value2);
        }

        /// <summary>
        /// Returns true iff the first value is smaller than the second value.
        /// </summary>
        /// <param name="value1">The first value to compare.</param>
        /// <param name="value2">The second value to compare.</param>
        /// <returns>True iff the first value is smaller than the second value.</returns>
        public static bool operator <(in UInt128 value1, in UInt128 value2)
        {
            return value1.CompareTo(value2) < 0;
        }

        /// <summary>
        /// Returns true iff the first value is greater than the second value.
        /// </summary>
        /// <param name="value1">The first value to compare.</param>
        /// <param name="value2">The second value to compare.</param>
        /// <returns>True iff the first value is greater than the second value.</returns>
        public static bool operator >(in UInt128 value1, in UInt128 value2)
        {
            return value1.CompareTo(value2) > 0;
        }

        /// <summary>
        /// Returns true iff the first value is smaller than or equal to the second value.
        /// </summary>
        /// <param name="value1">The first value to compare.</param>
        /// <param name="value2">The second value to compare.</param>
        /// <returns>True iff the first value is smaller than  or equal to the second value.</returns>
        public static bool operator <=(in UInt128 value1, in UInt128 value2)
        {
            return value1.CompareTo(value2) <= 0;
        }

        /// <summary>
        /// Returns true iff the first value is greater than or equal to the second value.
        /// </summary>
        /// <param name="value1">The first value to compare.</param>
        /// <param name="value2">The second value to compare.</param>
        /// <returns>True iff the first value is greater than  or equal to the second value.</returns>
        public static bool operator >=(in UInt128 value1, in UInt128 value2)
        {
            return value1.CompareTo(value2) >= 0;
        }

        /// <summary>
        /// Shifts its first operand right by the number of bits specified by its second operand.
        /// </summary>
        /// <param name="value">The value to shift.</param>
        /// <param name="numberOfBits">The number of bits to shift.</param>
        /// <returns>The value after it was shifted by the given number of bits.</returns>
        public static UInt128 operator >>(in UInt128 value, int numberOfBits)
        {
            return RightShift(value, numberOfBits);
        }

        /// <summary>
        /// Shifts its first operand left by the number of bits specified by its second operand.
        /// </summary>
        /// <param name="value">The value to shift.</param>
        /// <param name="numberOfBits">The number of bits to shift.</param>
        /// <returns>The value after it was shifted by the given number of bits.</returns>
        public static UInt128 operator <<(in UInt128 value, int numberOfBits)
        {
            return LeftShift(value, numberOfBits);
        }

        /// <summary>
        /// Shifts its first operand right by the number of bits specified by its second operand.
        /// </summary>
        /// <param name="value">The value to shift.</param>
        /// <param name="numberOfBits">The number of bits to shift.</param>
        /// <returns>The value after it was shifted by the given number of bits.</returns>
        public static UInt128 RightShift(in UInt128 value, int numberOfBits)
        {
            if (numberOfBits >= 128)
                return Zero;
            if (numberOfBits >= 64)
                return new UInt128(0, value.MostSignificant >> (numberOfBits - 64));
            if (numberOfBits == 0)
                return value;
            return new UInt128(value.MostSignificant >> numberOfBits, (value.LeastSignificant >> numberOfBits) + (value.MostSignificant << (64 - numberOfBits)));
        }

        /// <summary>
        /// Shifts its first operand left by the number of bits specified by its second operand.
        /// </summary>
        /// <param name="value">The value to shift.</param>
        /// <param name="numberOfBits">The number of bits to shift.</param>
        /// <returns>The value after it was shifted by the given number of bits.</returns>
        public static UInt128 LeftShift(in UInt128 value, int numberOfBits)
        {
            numberOfBits %= 128;
            if (numberOfBits >= 64)
                return new UInt128(value.LeastSignificant << (numberOfBits - 64), 0);
            if (numberOfBits == 0)
                return value;
            return new UInt128((value.MostSignificant << numberOfBits) + (value.LeastSignificant >> (64 - numberOfBits)), value.LeastSignificant << numberOfBits);
        }

        /// <summary>
        /// Bitwise ands between two values.
        /// </summary>
        /// <param name="value1">The first value to do bitwise and.</param>
        /// <param name="value2">The second value to do bitwise and.</param>
        /// <returns>The two values after they were bitwise anded.</returns>
        public static UInt128 operator &(in UInt128 value1, in UInt128 value2)
        {
            return BitwiseAnd(value1, value2);
        }

        /// <summary>
        /// Bitwise ands between two values.
        /// </summary>
        /// <param name="value1">The first value to do bitwise and.</param>
        /// <param name="value2">The second value to do bitwise and.</param>
        /// <returns>The two values after they were bitwise anded.</returns>
        public static UInt128 BitwiseAnd(in UInt128 value1, in UInt128 value2)
        {
            return new UInt128(value1.MostSignificant & value2.MostSignificant, value1.LeastSignificant & value2.LeastSignificant);
        }

        /// <summary>
        /// Bitwise ors between two values.
        /// </summary>
        /// <param name="value1">The first value to do bitwise or.</param>
        /// <param name="value2">The second value to do bitwise or.</param>
        /// <returns>The two values after they were bitwise ored.</returns>
        public static UInt128 operator |(in UInt128 value1, in UInt128 value2)
        {
            return BitwiseOr(value1, value2);
        }

        /// <summary>
        /// Bitwise ors between two values.
        /// </summary>
        /// <param name="value1">The first value to do bitwise or.</param>
        /// <param name="value2">The second value to do bitwise or.</param>
        /// <returns>The two values after they were bitwise ored.</returns>
        public static UInt128 BitwiseOr(in UInt128 value1, in UInt128 value2)
        {
            return new UInt128(value1.MostSignificant | value2.MostSignificant, value1.LeastSignificant | value2.LeastSignificant);
        }

        /// <summary>
        /// Sums the given values and returns the sum.
        /// </summary>
        /// <param name="value1">The first value to sum.</param>
        /// <param name="value2">The second value to sum.</param>
        /// <returns>The sum of the given values.</returns>
        public static UInt128 operator +(in UInt128 value1, in UInt128 value2)
        {
            return Add(value1, value2);
        }

        /// <summary>
        /// Sums the given values and returns the sum.
        /// </summary>
        /// <param name="value1">The first value to sum.</param>
        /// <param name="value2">The second value to sum.</param>
        /// <returns>The sum of the given values.</returns>
        public static UInt128 Add(in UInt128 value1, in UInt128 value2)
        {
            ulong leastSignificant = value1.LeastSignificant + value2.LeastSignificant;
            bool overflow = (leastSignificant < Math.Max(value1.LeastSignificant, value2.LeastSignificant));
            return new UInt128(value1.MostSignificant + value2.MostSignificant + (ulong)(overflow ? 1 : 0), leastSignificant);
        }

        /// <summary>
        /// Substract the second value from the first value and returns the result of the substraction.
        /// </summary>
        /// <param name="value1">The first value to sum.</param>
        /// <param name="value2">The second value to sum.</param>
        /// <returns>The result of substracting the second value from the first value.</returns>
        public static UInt128 operator -(in UInt128 value1, in UInt128 value2)
        {
            return Subtract(value1, value2);
        }

        /// <summary>
        /// Substract the second value from the first value and returns the result of the substraction.
        /// </summary>
        /// <param name="value1">The first value to sum.</param>
        /// <param name="value2">The second value to sum.</param>
        /// <returns>The result of substracting the second value from the first value.</returns>
        public static UInt128 Subtract(in UInt128 value1, in UInt128 value2)
        {
            ulong leastSignificant = value1.LeastSignificant - value2.LeastSignificant;
            bool overflow = (leastSignificant > value1.LeastSignificant);
            return new UInt128(value1.MostSignificant - value2.MostSignificant - (ulong)(overflow ? 1 : 0), leastSignificant);
        }

        /// <summary>
        /// Returns the hash code for this instance.
        /// </summary>
        /// <returns>
        /// A 32-bit signed integer that is the hash code for this instance.
        /// </returns>
        /// <filterpriority>2</filterpriority>
        public override int GetHashCode()
        {
            return MostSignificant.GetHashCode() + LeastSignificant.GetHashCode();
        }

        /// <summary>
        /// Converts the numeric value of the current <see cref="UInt128"/> object to its equivalent string representation by using the specified format and culture-specific format information.
        /// </summary>
        /// <param name="format">A standard or custom numeric format string.</param>
        /// <param name="formatProvider">An object that supplies culture-specific formatting information.</param>
        /// <returns>The string representation of the current <see cref="UInt128"/> value as specified by the <paramref name="format"/> and <paramref name="formatProvider"/> parameters.</returns>
        /// <exception cref="FormatException"><paramref name="format"/> is not a valid format string.</exception>
        /// <remarks>
        /// The <paramref name="format"/> parameter can be any valid standard numeric format specifier, or any combination of custom numeric format specifiers. 
        /// If <paramref name="format"/> is equal to <see cref="String.Empty"/> or is <see langword="null"/>, the return value of the current <see cref="UInt128"/> object is formatted with the general format specifier ("G"). 
        /// If <paramref name="format"/> is any other value, the method throws a <see cref="FormatException"/>.
        /// <para>
        /// The <paramref name="formatProvider"/> parameter is an <see cref="IFormatProvider"/> implementation. 
        /// Its <see cref="IFormatProvider.GetFormat"/> method returns a <see cref="NumberFormatInfo"/> object that provides culture-specific information about the format of the string returned by this method. 
        /// When the <see cref="ToString(String, IFormatProvider)"/> method is invoked, it calls the <paramref name="formatProvider"/> parameter's <see cref="IFormatProvider.GetFormat"/> method and passes it a <see cref="Type"/> object that represents the <see cref="NumberFormatInfo"/> type. 
        /// The <see cref="IFormatProvider.GetFormat"/> method then returns the <see cref="NumberFormatInfo"/> object that provides information for formatting the <see cref="UInt128"/> object, such as the negative sign symbol, the group separator symbol, or the decimal point symbol. 
        /// There are three ways to use the <paramref name="formatProvider"/> parameter to supply formatting information to the <see cref="ToString(String, IFormatProvider)"/> method: 
        /// <list type="bullet">
        ///   <item>
        ///   You can pass a <see cref="CultureInfo"/> object that represents the culture that provides numeric formatting information. 
        ///   Its <see cref="CultureInfo.GetFormat"/> method returns the <see cref="NumberFormatInfo"/> object that provides numeric formatting information.
        ///   </item>
        ///   <item>You can pass the actual <see cref="NumberFormatInfo"/> object that provides formatting information. (Its implementation of <see cref="NumberFormatInfo.GetFormat"/> just returns itself.)</item>
        ///   <item>
        ///   You can pas a custom object that implements <see cref="IFormatProvider"/> and uses the <see cref="IFormatProvider.GetFormat"/> method 
        ///   to instantiate and return the <see cref="NumberFormatInfo"/> object that provides formatting information.
        ///   </item>
        /// </list>
        /// If <paramref name="formatProvider"/> is <see langword="null"/>, the formatting of the returned string is based on the <see cref="NumberFormatInfo "/> object of the current culture.
        /// </para>
        /// </remarks>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            string bigIntegerString = ((BigInteger)this).ToString(format, formatProvider);
            if (MostSignificant >> 63 == 1 && bigIntegerString[0] == '0')
                return bigIntegerString[1..];
            return bigIntegerString;
        }

        /// <summary>
        /// Converts the numeric value of the current <see cref="UInt128"/> object to its equivalent string representation by using the specified format.
        /// Uses <see cref="CultureInfo.CurrentCulture"/> as the format provider.
        /// </summary>
        /// <param name="format">A standard or custom numeric format string.</param>
        /// <returns>The string representation of the current <see cref="UInt128"/> value as specified by the <paramref name="format"/> parameter.</returns>
        /// <exception cref="FormatException"><paramref name="format"/> is not a valid format string.</exception>
        /// <remarks>
        /// See <see cref="ToString(string, IFormatProvider)"/> for remarks.
        /// </remarks>
        public string ToString(string format)
        {
            return ToString(format, CultureInfo.CurrentCulture);
        }

        /// <summary>
        /// Converts the numeric value of the current <see cref="UInt128"/> object to its equivalent string representation by using the specified culture-specific format information.
        /// Uses "G" format.
        /// </summary>
        /// <param name="provider">An object that supplies culture-specific formatting information.</param>
        /// <returns>The string representation of the current <see cref="UInt128"/> value as specified by the <paramref name="provider"/> parameter.</returns>
        /// <remarks>
        /// See <see cref="ToString(string, IFormatProvider)"/> for remarks.
        /// </remarks>
        public string ToString(IFormatProvider provider)
        {
            return ToString("G", provider);
        }

        /// <summary>
        /// Converts the numeric value of the current <see cref="UInt128"/> object to its equivalent string representation.
        /// Uses "G" format.
        /// Uses <see cref="CultureInfo.CurrentCulture"/> as the format provider.
        /// </summary>
        /// <returns>The string representation of the current <see cref="UInt128"/> value.</returns>
        /// <remarks>
        /// See <see cref="ToString(string, IFormatProvider)"/> for remarks.
        /// </remarks>
        public override string ToString()
        {
            return ToString(CultureInfo.CurrentCulture);
        }

        private BigInteger ToBigInteger()
        {
            BigInteger value = MostSignificant;
            value <<= 64;
            value += LeastSignificant;
            return value;
        }

        /// <summary>
        /// Get the least significate ulong
        /// </summary>
        public ulong LeastSignificant;

        /// <summary>
        /// Get the most significant ulong
        /// </summary>
        public ulong MostSignificant;
    }
}
