using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace IPBan
{
    public static class IPBanFirewall
    {
        private static void AppendRange(StringBuilder b, PortRange range)
        {
            string rangeString = range.ToString();
            if (rangeString != null)
            {
                b.Append(range);
                b.Append(',');
            }
        }

        /// <summary>
        /// Get a port range of block ports except the passed in port ranges
        /// </summary>
        /// <param name="portRanges">Port ranges to allow, all other ports are blocked</param>
        /// <returns>Port range string to block (i.e. 0-79,81-442,444-65535)</returns>
        public static string GetPortRangeStringBlockExcept(IEnumerable<PortRange> portRanges)
        {
            if (portRanges == null)
            {
                return null;
            }
            StringBuilder b = new StringBuilder();
            int currentPort = 0;
            foreach (PortRange range in portRanges.Where(r => r.IsValid).OrderBy(r => r.MinPort))
            {
                // if current port less than min, append range
                if (currentPort < range.MinPort)
                {
                    int maxPort = range.MinPort - 1;
                    AppendRange(b, new PortRange(currentPort, maxPort));
                    currentPort = range.MaxPort + 1;
                }
                // if current port in range, append the overlapped range
                else if (currentPort >= range.MinPort && currentPort <= range.MaxPort)
                {
                    AppendRange(b, new PortRange(range.MinPort, currentPort));
                    currentPort++;
                }
                // append the after range to current port
                else if (currentPort <= range.MaxPort)
                {
                    AppendRange(b, new PortRange(range.MaxPort + 1, currentPort));
                    currentPort++;
                }
            }
            if (currentPort != 0)
            {
                AppendRange(b, new PortRange(currentPort, 65535));
            }

            // trim ending comma
            if (b.Length != 0)
            {
                b.Length--;
            }
            return (b.Length == 0 ? null : b.ToString());
        }

        /// <summary>
        /// Get a port range of allow ports. Overlaps are thrown out.
        /// </summary>
        /// <param name="portRanges">Port ranges to allow</param>
        /// <returns>Port range string to allow (i.e. 80,443,1000-10010)</returns>
        public static string GetPortRangeStringAllow(IEnumerable<PortRange> portRanges)
        {
            StringBuilder b = new StringBuilder();
            if (portRanges != null)
            {
                int lastMax = -1;
                foreach (PortRange range in portRanges.OrderBy(p => p.MinPort))
                {
                    if (range.MinPort > lastMax)
                    {
                        AppendRange(b, range);
                        lastMax = range.MaxPort;
                    }
                }
            }

            // trim end comma
            if (b.Length != 0)
            {
                b.Length--;
            }
            return (b.Length == 0 ? null : b.ToString());
        }
    }
}
