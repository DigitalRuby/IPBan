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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Utility methods for working with firewall data
    /// </summary>
    public static class IPBanFirewallUtility
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
        /// Create a firewall
        /// </summary>
        /// <param name="allTypes">Firewall types</param>
        /// <param name="rulePrefix">Rule prefix or null for default</param>
        /// <param name="previousFirewall">Current firewall</param>
        /// <returns>Firewall</returns>
        public static IIPBanFirewall CreateFirewall(IReadOnlyCollection<Type> allTypes,
            string rulePrefix = null,
            IIPBanFirewall previousFirewall = null)
        {

#pragma warning disable IL2072

            try
            {
                int priority = int.MinValue;
                Type firewallType = typeof(IIPBanFirewall);
                Type fallbackType = null;

                var q =
                    from fwType in allTypes
                    where fwType.IsPublic &&
                        fwType != firewallType &&
                        firewallType.IsAssignableFrom(fwType) &&
                        (fwType.GetCustomAttribute<RequiredOperatingSystemAttribute>(false)?.IsMatch ?? false)
                    select new
                    {
                        FirewallType = fwType,
                        OS = fwType.GetCustomAttribute<RequiredOperatingSystemAttribute>(false)
                    };
                var array = q.OrderBy(f => f.OS.Priority).ToArray();
                foreach (var result in array)
                {
                    bool matchPriority = priority < result.OS.Priority;
                    if (matchPriority)
                    {
                        firewallType = result.FirewallType;
                        priority = result.OS.Priority;
                        fallbackType = result.OS.FallbackFirewallType;
                    }
                }
                if (firewallType is null || firewallType == typeof(IIPBanFirewall))
                {
                    throw new ArgumentException("Firewall is null, at least one type should implement IIPBanFirewall");
                }
                RequiredOperatingSystemAttribute fallbackAttr = fallbackType?.GetCustomAttribute<RequiredOperatingSystemAttribute>();
                Type existingType = previousFirewall?.GetType();
                if (existingType != null && // if we have an existing firewall and
                (
                    firewallType.Equals(existingType)) || // if the existing firewall is the desired type or
                    (
                        fallbackType != null && // we have a fallback type and
                        (
                            fallbackType.Equals(existingType) || // the existing firewall is the fallback type or
                            (
                                // the fallback firewall has another fallback firewall and it matches the existing type
                                fallbackAttr?.FallbackFirewallType != null && fallbackAttr.FallbackFirewallType.Equals(existingType)
                            )
                        )
                    )
                )
                {
                    return previousFirewall;
                }
                try
                {
                    return Activator.CreateInstance(firewallType, [rulePrefix]) as IIPBanFirewall;
                }
                catch (Exception ex)
                {
                    // see if there's a fallback
                    if (fallbackType is null)
                    {
                        throw;
                    }
                    Logger.Error(ex, "Failed to create firewall of type {0}, falling back to firewall type {1}", firewallType, fallbackType);
                    try
                    {
                        return Activator.CreateInstance(fallbackType, [rulePrefix]) as IIPBanFirewall;
                    }
                    catch (Exception ex2)
                    {
                        // last fallback attempt
                        if (fallbackAttr?.FallbackFirewallType is null)
                        {
                            throw;
                        }
                        Logger.Error(ex2, "Failed to create firewall of type {0}, falling back to final attempt with firewall type {1}", fallbackType, fallbackAttr.FallbackFirewallType);
                        return Activator.CreateInstance(fallbackAttr.FallbackFirewallType, [rulePrefix]) as IIPBanFirewall;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to create firewall, please double check your Firewall configuration property", ex);
            }

#pragma warning restore

        }

        /// <summary>
        /// Invert port ranges. For example, if just port 80 was open, inverting it would get you 0-79, 81-65535.
        /// </summary>
        /// <param name="portRanges">Port ranges</param>
        /// <returns>Inverted port ranges</returns>
        public static IReadOnlyCollection<PortRange> InvertPortRanges(IEnumerable<PortRange> portRanges)
        {
            const int MinPort = 0;
            const int MaxPort = 65535;

            if (portRanges is null)
            {
                return null;
            }

            var mergedRanges = MergePortRanges(portRanges);
            if (mergedRanges is null)
            {
                return null;
            }

            List<PortRange> result = [];
            int current = MinPort;

            foreach (var range in mergedRanges)
            {
                if (range.MinPort > current)
                {
                    result.Add(new PortRange { MinPort = current, MaxPort = range.MinPort - 1 });
                }

                if (range.MaxPort + 1 > current)
                {
                    current = range.MaxPort + 1;
                }
            }

            if (current <= MaxPort)
            {
                result.Add(new PortRange { MinPort = current, MaxPort = MaxPort });
            }

            return result;
        }

        /// <summary>
        /// Merge port ranges
        /// </summary>
        /// <param name="portRanges">Port ranges</param>
        /// <returns>Distinct port ranges</returns>
        public static IReadOnlyCollection<PortRange> MergePortRanges(IEnumerable<PortRange> portRanges)
        {
            var sortedRanges = portRanges
                .Where(x => x.IsValid)
                .OrderBy(x => x.MinPort)
                .ThenBy(x => x.MaxPort)
                .Distinct()
                .ToList();
            if (sortedRanges.Count == 0)
            {
                return null;
            }

            List<PortRange> result = [sortedRanges[0]];
            foreach (var range in sortedRanges.Skip(1))
            {
                var lastRange = result.Last();
                if (range.MinPort <= lastRange.MaxPort)
                {
                    lastRange.MaxPort = range.MaxPort;
                    result[^1] = lastRange; // struct, must assign back into list
                }
                else
                {
                    result.Add(range);
                }
            }

            return result;
        }

        /// <summary>
        /// Get a port range of block ports given a set of allowed port ranges
        /// </summary>
        /// <param name="allowPortRanges">Port ranges to allow, all other ports are blocked</param>
        /// <returns>Port range string to block (i.e. 0-79,81-442,444-65535) - null if none to block.</returns>
        public static string GetPortRangeStringBlock(IEnumerable<PortRange> allowPortRanges)
        {
            // handle null
            if (allowPortRanges is null)
            {
                return null;
            }

            IReadOnlyCollection<PortRange> blockPortRanges = InvertPortRanges(allowPortRanges);

            // handle null again
            if (blockPortRanges is null)
            {
                return null;
            }

            StringBuilder portRangeStringBuilder = new();
            foreach (PortRange portRange in blockPortRanges)
            {
                AppendRange(portRangeStringBuilder, portRange);
            }

            // trim ending comma
            if (portRangeStringBuilder.Length != 0)
            {
                portRangeStringBuilder.Length--;
            }
            return (portRangeStringBuilder.Length == 0 ? null : portRangeStringBuilder.ToString());
        }

        /// <summary>
        /// Get a port range of allow ports. Overlaps are thrown out.
        /// </summary>
        /// <param name="allowPortRanges">Port ranges to allow</param>
        /// <returns>Port range string to allow (i.e. 80,443,1000-10010) - null if none to allow.</returns>
        public static string GetPortRangeStringAllow(IEnumerable<PortRange> allowPortRanges)
        {
            var result = MergePortRanges(allowPortRanges);
            return result is null || result.Count == 0 ? null : string.Join(',', result.Select(x => x.ToString()));
        }

        /// <summary>
        /// Get port ranges that will be applicable to a block or allow rule
        /// </summary>
        /// <param name="portRanges">Port ranges</param>
        /// <param name="block">True if block, false if allow</param>
        /// <returns>Port ranges for rule, will never be null</returns>
        public static IEnumerable<PortRange> GetPortRangesForRule(IEnumerable<PortRange> portRanges, bool block)
        {
            // process port ranges, if any
            if (portRanges is not null)
            {
                string portRangeString;
                if (block)
                {
                    portRangeString = IPBanFirewallUtility.GetPortRangeStringBlock(portRanges);
                }
                else
                {
                    portRangeString = IPBanFirewallUtility.GetPortRangeStringAllow(portRanges);
                }
                if (portRangeString is not null)
                {
                    portRanges = portRangeString.Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => PortRange.Parse(s));
                }
                else
                {
                    portRanges = [];
                }
            }
            else
            {
                portRanges = [];
            }
            return portRanges;
        }

        /// <summary>
        /// Filter ip address ranges from ranges using filter
        /// </summary>
        /// <param name="ranges">Ip address ranges to filter</param>
        /// <param name="filter">Ip address ranges to filter out of ranges, null for no filtering</param>
        /// <returns>Filtered ip address ranges in sorted order</returns>
        public static IEnumerable<IPAddressRange> FilterRanges(this IEnumerable<IPAddressRange> ranges, IEnumerable<IPAddressRange> filter)
        {
            // if null ranges we are done
            if (ranges is null)
            {
                yield break;
            }

            // if null filter, return ranges as is
            else if (filter is null)
            {
                foreach (IPAddressRange range in ranges.OrderBy(r => r))
                {
                    yield return range;
                }
                yield break;
            }

            using IEnumerator<IPAddressRange> rangeEnum = ranges.OrderBy(r => r).GetEnumerator();
            using IEnumerator<IPAddressRange> filterEnum = filter.OrderBy(r => r).GetEnumerator();
            // if no ranges left, we are done
            if (!rangeEnum.MoveNext())
            {
                yield break;
            }

            IPAddressRange currentFilter = (filterEnum.MoveNext() ? filterEnum.Current : null);
            IPAddressRange currentRange = rangeEnum.Current;
            while (true)
            {
                // if no more filter, just continue returning ranges as is
                if (currentFilter is null)
                {
                    yield return currentRange;
                    if (!rangeEnum.MoveNext())
                    {
                        break;
                    }
                    continue;
                }

                int compare = currentFilter.Begin.CompareTo(currentRange.End);
                if (compare > 0)
                {
                    // current filter begin is after the range end, just return the range as is
                    yield return currentRange;
                    if (!rangeEnum.MoveNext())
                    {
                        break;
                    }
                    currentRange = rangeEnum.Current;
                }
                else
                {
                    compare = currentFilter.End.CompareTo(currentRange.Begin);

                    // check if the current filter end is before the range begin
                    if (compare < 0)
                    {
                        // current filter end is before the range begin, move to next filter
                        currentFilter = (filterEnum.MoveNext() ? filterEnum.Current : null);
                    }
                    else
                    {
                        // the current filter is inside the current range, filter
                        int compareBegin = currentFilter.Begin.CompareTo(currentRange.Begin);
                        int compareEnd = currentFilter.End.CompareTo(currentRange.End);
                        if (compareBegin <= 0)
                        {
                            // filter begin is less than or equal to the range begin
                            if (compareEnd < 0 && currentFilter.End.TryIncrement(out IPAddress begin))
                            {
                                // set the range to have the filtered portion removed
                                currentRange = new IPAddressRange(begin, currentRange.End);

                                // move to next filter
                                currentFilter = (filterEnum.MoveNext() ? filterEnum.Current : currentFilter);
                            }
                            else
                            {
                                // else the filter has blocked out this entire range, ignore it
                                if (!rangeEnum.MoveNext())
                                {
                                    break;
                                }
                                currentRange = rangeEnum.Current;
                            }
                        }
                        else
                        {
                            // if compareBegin was >= the ip address range begin, we won't get here
                            // this means the current filter begin must be greater than 0
                            if (!currentFilter.Begin.TryDecrement(out IPAddress end))
                            {
                                throw new InvalidOperationException("Current filter should have been able to decrement the begin ip address");
                            }

                            // filter begin is after the range begin, return the range begin and one before the filter begin
                            yield return new IPAddressRange(currentRange.Begin, end);
                            if (!currentFilter.End.TryIncrement(out IPAddress newBegin))
                            {
                                newBegin = currentFilter.End;
                            }

                            if (newBegin.CompareTo(currentRange.End) > 0)
                            {
                                // end of range, get a new range
                                if (!rangeEnum.MoveNext())
                                {
                                    break;
                                }
                                currentRange = rangeEnum.Current;
                            }
                            else
                            {
                                currentRange = new IPAddressRange(newBegin, currentRange.End);
                            }
                        }
                    }
                }
            }
        }
    }
}
