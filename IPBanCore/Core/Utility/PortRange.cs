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

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Represents a range of ports
    /// </summary>
    public struct PortRange
    {
        /// <summary>
        /// Min port, inclusive
        /// </summary>
        public int MinPort { get; }

        /// <summary>
        /// Max port, inclusive
        /// </summary>
        public int MaxPort { get; }

        /// <summary>
        /// Return whether the range is valid
        /// </summary>
        public bool IsValid { get { return MinPort <= MaxPort && MinPort >= 0 && MinPort <= 65535 && MaxPort >= 0 && MaxPort <= 65535; } }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="port">Set min and max to this port</param>
        public PortRange(int port)
        {
            MinPort = MaxPort = port;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="minPort">Min port</param>
        /// <param name="maxPort">Max port</param>
        public PortRange(int minPort, int maxPort)
        {
            MinPort = minPort;
            MaxPort = maxPort;
        }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String or null if invalid range</returns>
        public override string ToString()
        {
            if (MinPort > 65535 || MaxPort > 65535 || MinPort < 0 || MaxPort < 0 || MaxPort < MinPort)
            {
                return null;
            }
            else if (MinPort == MaxPort)
            {
                return MinPort.ToString(CultureInfo.InvariantCulture);
            }
            return MinPort.ToString(CultureInfo.InvariantCulture) + "-" + MaxPort.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Convert port range to string implicitly.
        /// </summary>
        /// <param name="range">Port range</param>
        /// <returns>String</returns>
        public static implicit operator string(PortRange range)
        {
            return range.ToString();
        }

        /// <summary>
        /// Check if port range contains a port
        /// </summary>
        /// <param name="port">Port</param>
        /// <returns>True if contains the port, false otherwise</returns>
        public bool Contains(int port)
        {
            return port >= MinPort && port <= MaxPort;
        }

        /// <summary>
        /// Parse a port range from a string. If parsing fails, min port will be -1.
        /// </summary>
        /// <param name="s">String</param>
        /// <returns>PortRange</returns>
        public static PortRange Parse(string s)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                return new PortRange(-1, -1);
            }
            s = s.Trim();
            if (s.StartsWith('-'))
            {
                return new PortRange(-1, -1);
            }
            string[] pieces = s.Split('-', StringSplitOptions.RemoveEmptyEntries);
            if (pieces.Length == 1)
            {
                if (int.TryParse(pieces[0], NumberStyles.Any, CultureInfo.InvariantCulture, out int singlePort))
                {
                    return new PortRange(singlePort);
                }

            }
            else if (pieces.Length == 2)
            {
                if (int.TryParse(pieces[0], NumberStyles.Any, CultureInfo.InvariantCulture, out int singlePort1) &&
                    int.TryParse(pieces[1], NumberStyles.Any, CultureInfo.InvariantCulture, out int singlePort2))
                {
                    return new PortRange(singlePort1, singlePort2);
                }
            }
            return new PortRange(-1, -1);
        }

        /// <summary>
        /// Parse port range from string implicitly. If parsing fails, min port will be -1.
        /// </summary>
        /// <param name="s">Port range string</param>
        /// <returns>PortRange</returns>
        public static implicit operator PortRange(string s)
        {
            return Parse(s);
        }
    }
}
