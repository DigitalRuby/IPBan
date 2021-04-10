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

using System.Collections.Generic;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Interface for filtering checks
    /// </summary>
    public interface IIPBanFilter
    {
        /// <summary>
        /// Check if two filters are equal
        /// </summary>
        /// <param name="other">Other filter</param>
        /// <returns>True if both equal, false otherwise</returns>
        bool Equals(IIPBanFilter other);

        /// <summary>
        /// Check if an entry is filtered
        /// </summary>
        /// <param name="entry">Entry</param>
        /// <returns>True if whitelisted, false otherwise</returns>
        bool IsFiltered(string entry);

        /// <summary>
        /// Check if an ip address range is filtered. If any ip or range intersects, the range is filtered.
        /// </summary>
        /// <param name="range">Range</param>
        /// <returns>True if range is whitelisted, false otherwise</returns>
        bool IsFiltered(IPAddressRange range);

        /// <summary>
        /// Gets all ip address ranges in the filter
        /// </summary>
        IReadOnlyCollection<IPAddressRange> IPAddressRanges { get; }

        /// <summary>
        /// Regex for further filtering
        /// </summary>
        public System.Text.RegularExpressions.Regex Regex { get; }
    }
}
