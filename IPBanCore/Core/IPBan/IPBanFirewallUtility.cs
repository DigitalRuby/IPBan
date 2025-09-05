/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

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
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;

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
                        fallbackAttr = fallbackType?.GetCustomAttribute<RequiredOperatingSystemAttribute>();
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
            if (portRanges is null)
            {
                return null;
            }

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
        /// Get port range string without modifying the ranges
        /// </summary>
        /// <param name="portRanges">Port ranges</param>
        /// <returns>String</returns>
        public static string GetPortRangeString(IEnumerable<PortRange> portRanges)
        {
            StringBuilder portRangeStringBuilder = new();

            foreach (PortRange portRange in portRanges)
            {
                AppendRange(portRangeStringBuilder, portRange);
            }

            // trim ending comma
            if (portRangeStringBuilder.Length != 0)
            {
                portRangeStringBuilder.Length--;
            }

            return portRangeStringBuilder.ToString();
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

        /// <summary>
        /// Restart rsys log on Linux
        /// </summary>
        public static void LinuxRestartRsyslog()
        {
            if (!OSUtility.IsLinux)
            {
                throw new PlatformNotSupportedException($"{nameof(LinuxRestartRsyslog)} can only be called on Linux");
            }

            // Attempt several strategies to reload rsyslog without assuming passwordless sudo.
            // 1. systemctl restart rsyslog
            // 2. service rsyslog restart (SysV compatibility)
            // 3. systemctl reload rsyslog
            // 4. pkill -HUP rsyslogd (last resort)
            string[][] commands =
            [
                ["systemctl", "restart", "rsyslog"],
                ["service", "rsyslog", "restart"],
                ["systemctl", "reload", "rsyslog"]
            ];
            bool success = false;
            foreach (var cmd in commands)
            {
                if (IPBanFirewallUtility.RunProcess(cmd[0], null, null, cmd[1], cmd[2]) == 0)
                {
                    success = true;
                    break;
                }
                Thread.Sleep(250);
            }
            if (!success)
            {
                // Try sending HUP directly
                if (IPBanFirewallUtility.RunProcess("pkill", null, null, "-HUP", "rsyslogd") != 0)
                {
                    Logger.Warn("Failed to reload rsyslog using systemctl/service/HUP; new log rule may not activate until rsyslog restarts");
                }
            }
        }

        /// <summary>
        /// Execute a firewall process
        /// </summary>
        /// <param name="program">Program</param>
        /// <param name="input">Input file or Stream to read and pipe to std in (null to not do this)</param>
        /// <param name="output">Dump std out to this file or Stream (null to not do this)</param>
        /// <param name="args">Args</param>
        /// <returns>Exit code</returns>
        public static int RunProcess(string program, object input, object output, params IEnumerable<string> args)
        {
            const int timeout = 60000; // 60 seconds in milliseconds

            string cmdLine = program + " " + string.Join(' ', args.Select(a => a?.ToString() ?? string.Empty));

#if ENABLE_FIREWALL_PROFILING

            StackTrace stackTrace = new();
            StringBuilder methods = new();
            var frames = stackTrace.GetFrames();
            foreach (var frame in frames)
            {
                if (methods.Length != 0) { methods.Append(" > "); }
                methods.Append(frame.GetMethod()?.Name);
            }
            Logger.Info("Running firewall process: {0}; stack: {1}", cmdLine, methods);

#else

            Logger.Debug("Running firewall process: {0}", cmdLine);

#endif

            var inputStream = input as Stream;
            var inputFile = input as string;
            var outputStream = output as Stream;
            var outputFile = output as string;
            bool redirectStdIn = inputStream is not null || inputFile is not null;
            bool redirectStdOut = outputStream is not null || outputFile is not null;

            using Process p = new()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = program,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true,
                    StandardErrorEncoding = ExtensionMethods.Utf8EncodingNoPrefix,
                    RedirectStandardInput = redirectStdIn,
                    RedirectStandardOutput = redirectStdOut,
                    StandardInputEncoding = redirectStdIn ? ExtensionMethods.Utf8EncodingNoPrefix : null,
                    StandardOutputEncoding = redirectStdOut ? ExtensionMethods.Utf8EncodingNoPrefix : null
                }
            };

            foreach (var arg in args)
            {
                var s = arg?.ToString();
                if (!string.IsNullOrEmpty(s)) { p.StartInfo.ArgumentList.Add(s); }
            }

            p.Start();

            MemoryStream stdErr = new();
            System.Threading.Tasks.Task errCopyTask = p.StandardError.BaseStream.CopyToAsync(stdErr);

            FileStream stdOutRedirection = null;
            System.Threading.Tasks.Task outCopyTask = null;
            if (redirectStdOut)
            {
                if (outputFile is not null)
                {
                    stdOutRedirection = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
                    outCopyTask = p.StandardOutput.BaseStream.CopyToAsync(stdOutRedirection);
                }
                else if (outputStream is not null)
                {
                    outCopyTask = p.StandardOutput.BaseStream.CopyToAsync(outputStream);
                }
            }

            if (redirectStdIn)
            {
                try
                {
                    if (inputFile is not null)
                    {
                        using var inFs = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
                        inFs.CopyTo(p.StandardInput.BaseStream);
                        p.StandardInput.Flush();
                    }
                    else if (inputStream is not null)
                    {
                        inputStream.CopyTo(p.StandardInput.BaseStream);
                    }
                }
                finally
                {
                    try { p.StandardInput.Close(); } catch { /* ignore */ }
                }
            }

            if (!p.WaitForExit(timeout))
            {
                Logger.Error("Process time out: {0}", cmdLine);
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                p.WaitForExit();
            }

            outCopyTask?.Wait(timeout);
            errCopyTask.Wait(timeout);

            if (stdErr.Length != 0)
            {
                Logger.Error("Process {0} had std err: {1}", cmdLine, Encoding.UTF8.GetString(stdErr.ToArray()));
            }
            if (p.ExitCode != 0)
            {
                Logger.Error("Process {0} had exit code {1}", cmdLine, p.ExitCode);
            }

            stdErr.Dispose();
            stdOutRedirection?.Dispose();

#if DEBUG

            //if (redirectStdIn) { Console.WriteLine("Process std in ({0}): {1}", cmdLine, File.ReadAllText(inputFile)); }
            //if (redirectStdOut) { Console.WriteLine("Process std out ({0}): {1}", cmdLine, File.ReadAllText(outputFile)); }

#endif

            return p.ExitCode;
        }

    }
}
