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

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Interface that determines if an ip address is whitelisted
    /// </summary>
    public interface IIsWhitelisted
    {
        /// <summary>
        /// Determines if an entry is whitelisted
        /// </summary>
        /// <param name="entry">Entry - can be ip address, user name, dns entry, etc.</param>
        /// <returns>True if the entry is whitelisted, false otherwise</returns>
        bool IsWhitelisted(string entry);

        /// <summary>
        /// Determines if an ip address range is whitelisted
        /// </summary>
        /// <param name="range">IP address range</param>
        /// <returns>True if any part of the range is whitelisted, false otherwise</returns>
        bool IsWhitelisted(IPAddressRange range);
    }
}
