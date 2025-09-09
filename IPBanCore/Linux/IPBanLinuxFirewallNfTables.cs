#define USE_NFT_NATIVE

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
#pragma warning disable SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time
#pragma warning disable IDE1006 // Naming Styles

namespace DigitalRuby.IPBanCore;

/// <summary>
/// NFTables firewall
/// </summary>
[RequiredOperatingSystem(OSUtility.Linux,
    Priority = 3,
    PriorityEnvironmentVariable = "IPBanPro_LinuxFirewallNFTablesPriority",
    FallbackFirewallType = typeof(IPBanLinuxFirewallD))]
[System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
public class IPBanLinuxFirewallNFTables : IPBanBaseFirewall
{

#if USE_NFT_NATIVE

    internal static class NftNative
    {
        internal const string LogicalName = "libnftables_logical";
        private static IntPtr _handle;

        static NftNative()
        {
            NativeLibrary.SetDllImportResolver(typeof(NftNative).Assembly, Resolve);
        }

        private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (!string.Equals(libraryName, LogicalName, StringComparison.Ordinal))
            {
                // not ours
                return IntPtr.Zero;
            }

            if (_handle != IntPtr.Zero)
            {
                // already loaded
                return _handle;
            }

            string[] candidates = ["libnftables.so.1", "libnftables.so"];

            foreach (var name in candidates)
            {
                // try with assembly and search path first, then without
                if (NativeLibrary.TryLoad(name, assembly, searchPath, out _handle))
                {
                    return _handle;
                }
                else if (NativeLibrary.TryLoad(name, out _handle))
                {
                    return _handle;
                }
            }

            throw new DllNotFoundException("Could not load libnftables (tried libnftables.so.1 and libnftables.so).");
        }

        private const string Dll = LogicalName;

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr nft_ctx_new(uint flags);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void nft_ctx_free(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int nft_ctx_buffer_output(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int nft_ctx_unbuffer_output(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr nft_ctx_get_output_buffer(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int nft_ctx_buffer_error(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int nft_ctx_unbuffer_error(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr nft_ctx_get_error_buffer(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int nft_run_cmd_from_buffer(IntPtr ctx, IntPtr buf);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int nft_run_cmd_from_filename(IntPtr ctx, IntPtr filename);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void nft_ctx_set_output(IntPtr ctx, IntPtr file);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void nft_ctx_set_error(IntPtr ctx, IntPtr file);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint nft_ctx_output_get_flags(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void nft_ctx_output_set_flags(IntPtr ctx, uint flags);
    }

    internal sealed class NftContext : IDisposable
    {
        private readonly Lock locker = new();
        private IntPtr ctx;

        public NftOutputFlags OutputFlags
        {
            get { lock (locker) return (NftOutputFlags)NftNative.nft_ctx_output_get_flags(ctx); }
            set { lock (locker) NftNative.nft_ctx_output_set_flags(ctx, (uint)value); }
        }

        public NftContext()
        {
            ctx = NftNative.nft_ctx_new(0);
            if (ctx == IntPtr.Zero)
            {
                throw new InvalidOperationException("nft_ctx_new returned NULL");
            }

            // default to buffered capture
            _ = NftNative.nft_ctx_buffer_output(ctx);
            _ = NftNative.nft_ctx_buffer_error(ctx);
        }

        public void Dispose()
        {
            lock (locker)
            {
                if (ctx != IntPtr.Zero)
                {
                    NftNative.nft_ctx_free(ctx);
                    ctx = IntPtr.Zero;
                }
            }
            GC.SuppressFinalize(this);
        }

        ~NftContext() => Dispose();

        // Run from an in-memory command string, capture UTF-8 bytes
        public int Run(byte[] command, out byte[] stdout, out byte[] stderr)
        {
            return RunInternal(() =>
            {
                GCHandle h = GCHandle.Alloc(command, GCHandleType.Pinned);
                try
                {
                    return NftNative.nft_run_cmd_from_buffer(ctx, h.AddrOfPinnedObject());
                }
                finally
                {
                    h.Free();
                }
            }, out stdout, out stderr);
        }

        public int RunFile(string inputFilePath, out byte[] stdout, out byte[] stderr)
        {
            return RunInternal(() =>
            {
                var utf8Bytes = ExtensionMethods.Utf8EncodingNoPrefix.GetBytes(inputFilePath);
                Array.Resize(ref utf8Bytes, utf8Bytes.Length + 1);
                utf8Bytes[^1] = 0; // null terminate
                GCHandle h = GCHandle.Alloc(utf8Bytes, GCHandleType.Pinned);
                try
                {
                    return NftNative.nft_run_cmd_from_filename(ctx, h.AddrOfPinnedObject());
                }
                finally
                {
                    h.Free();
                }
            }, out stdout, out stderr);
        }

        private int RunInternal(Func<int> invoker, out byte[] stdout, out byte[] stderr)
        {
            lock (locker)
            {
                _ = NftNative.nft_ctx_buffer_output(ctx);
                _ = NftNative.nft_ctx_buffer_error(ctx);

                var rc = invoker();

                stdout = PtrToBytes(NftNative.nft_ctx_get_output_buffer(ctx));
                stderr = PtrToBytes(NftNative.nft_ctx_get_error_buffer(ctx));

                _ = NftNative.nft_ctx_unbuffer_output(ctx);
                _ = NftNative.nft_ctx_unbuffer_error(ctx);

                return rc;
            }
        }

        private static byte[] PtrToBytes(IntPtr p)
        {
            if (p == IntPtr.Zero)
            {
                return [];
            }
            int len = 0;
            while (Marshal.ReadByte(p, len) != 0)
            {
                len++;
            }
            var result = new byte[len];
            Marshal.Copy(p, result, 0, len);
            return result;
        }
    }

    [Flags]
    internal enum NftOutputFlags : uint
    {
        NFT_CTX_OUTPUT_REVERSEDNS = (1 << 0),
        NFT_CTX_OUTPUT_SERVICE = (1 << 1),
        NFT_CTX_OUTPUT_STATELESS = (1 << 2),
        NFT_CTX_OUTPUT_HANDLE = (1 << 3),
        NFT_CTX_OUTPUT_JSON = (1 << 4),
        NFT_CTX_OUTPUT_ECHO = (1 << 5),
        NFT_CTX_OUTPUT_GUID = (1 << 6),
        NFT_CTX_OUTPUT_NUMERIC_PROTO = (1 << 7),
        NFT_CTX_OUTPUT_NUMERIC_PRIO = (1 << 8),
        NFT_CTX_OUTPUT_NUMERIC_SYMBOL = (1 << 9),
        NFT_CTX_OUTPUT_NUMERIC_TIME = (1 << 10),
        NFT_CTX_OUTPUT_NUMERIC_ALL = (NFT_CTX_OUTPUT_NUMERIC_PROTO |
                                         NFT_CTX_OUTPUT_NUMERIC_PRIO |
                                         NFT_CTX_OUTPUT_NUMERIC_SYMBOL |
                                         NFT_CTX_OUTPUT_NUMERIC_TIME),
        NFT_CTX_OUTPUT_TERSE = (1 << 11),
    }

    private readonly NftContext nftCtx = new()
    {
        OutputFlags = NftOutputFlags.NFT_CTX_OUTPUT_JSON | NftOutputFlags.NFT_CTX_OUTPUT_HANDLE
    };

#endif

    private const int sixtyFourK = 64 * 1024;

    private const string tableName = "ipbanx";
    private const string chainName = "ipbanx_input";

    private const string internalRuleCommentPrefix = "ipbanxrule_";

    private static readonly Regex commentRegex = new(@$"{internalRuleCommentPrefix}(?<ruleName>[a-z0-9_]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Internal rule representation
    /// </summary>
    /// <param name="Name">Name</param>
    /// <param name="Allow">Allow</param>
    /// <param name="Ports">Ports</param>
    /// <param name="Entries">Entries</param>
    private record NftRuleInternal(string Name, bool Allow, IReadOnlyCollection<PortRange> Ports, IReadOnlyCollection<string> Entries);

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="rulePrefix">Rule prefix</param>
    public IPBanLinuxFirewallNFTables(string rulePrefix = null) : base(rulePrefix)
    {
        // will throw if nft not installed and fallback to firewalld
        OSUtility.StartProcessAndWait("sudo", "nft -v");
        Initialize();
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        base.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public override void Truncate()
    {
        RunNft("destroy", "table", "inet", tableName);
        Initialize();
    }

    #region Public API

    /// <inheritdoc />
    public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        => AllowIPAddresses(AllowRulePrefix, ipAddresses.Where(i => IPAddress.TryParse(i, out _))
            .Select(i => new IPAddressRange(IPAddress.Parse(i))), null, cancelToken);

    /// <inheritdoc />
    public override Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
    {
        string fullRuleName = GetFullRuleName(ruleNamePrefix);
        var setV4 = fullRuleName + "4";
        var setV6 = fullRuleName + "6";
        EnsureSets(setV4, "ipv4_addr", setV6, "ipv6_addr");
        BatchUpdateSets(setV4, setV6, ipAddresses);
        EnsureRules(fullRuleName, allowedPorts, allow: true);
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        => BlockIPAddresses(ruleNamePrefix, ipAddresses.Where(i => IPAddress.TryParse(i, out _))
            .Select(i => new IPAddressRange(IPAddress.Parse(i))), allowedPorts, cancelToken);

    /// <inheritdoc />
    public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
    {
        string fullRuleName = GetFullRuleName(ruleNamePrefix);
        var setV4 = fullRuleName + "4";
        var setV6 = fullRuleName + "6";
        EnsureSets(setV4, "ipv4_addr", setV6, "ipv6_addr");
        List<IPAddressRange> addsV4 = [];
        List<IPAddressRange> addsV6 = [];
        List<IPAddressRange> delsV4 = [];
        List<IPAddressRange> delsV6 = [];
        // use hash sets, no ordering required for correctness
        HashSet<IPAddress> deltaAdds = [];
        HashSet<IPAddress> deltaRemoves = [];
        foreach (var delta in ipAddresses)
        {
            if (!IPAddress.TryParse(delta.IPAddress, out var ip))
            {
                Logger.Debug("Skipping delta {0} because it is not a single IP address", delta.IPAddress);
                continue;
            }
            if (delta.Added)
            {
                deltaAdds.Add(ip);
            }
            else
            {
                deltaRemoves.Add(ip);
            }
        }
        foreach (var ip in deltaAdds)
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                addsV4.Add(new IPAddressRange(ip));
            }
            else
            {
                addsV6.Add(new IPAddressRange(ip));
            }
        }
        foreach (var ip in deltaRemoves)
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                delsV4.Add(new IPAddressRange(ip));
            }
            else
            {
                delsV6.Add(new IPAddressRange(ip));
            }
        }
        BatchUpdateSetsDelta(setV4, setV6, addsV4, addsV6, delsV4, delsV6);
        EnsureRules(fullRuleName, allowedPorts, allow: false);
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
    {
        string fullRuleName = GetFullRuleName(ruleNamePrefix);
        var setV4 = fullRuleName + "4";
        var setV6 = fullRuleName + "6";
        EnsureSets(setV4, "ipv4_addr", setV6, "ipv6_addr");
        BatchUpdateSets(setV4, setV6, ranges);
        EnsureRules(fullRuleName, allowedPorts, allow: false);
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public override IEnumerable<string> EnumerateAllowedIPAddresses(string ruleNamePrefix = null) =>
        EnumerateAllSetIPs(true, ruleNamePrefix).SelectMany(s => s.Entries);

    /// <inheritdoc />
    public override IEnumerable<string> EnumerateBannedIPAddresses(string ruleNamePrefix = null) =>
        EnumerateAllSetIPs(false, ruleNamePrefix).SelectMany(s => s.Entries);

    /// <inheritdoc />
    public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
    {
        foreach (var ip in EnumerateAllSetIPs(null).SelectMany(s => s.Entries))
        {
            if (IPAddressRange.TryParse(ip, out var r))
            {
                yield return r;
            }
        }
    }

    /// <inheritdoc />
    public override bool DeleteRule(string ruleName)
    {
        ruleName = GetFullRuleName(ruleName);
        RemoveRule(ruleName);
        RemoveSet(ruleName);
        return true;
    }

    /// <inheritdoc />
    public override string GetPorts(string ruleName)
    {
        // Normalize to base rule name (unsuffixed)
        string baseName = GetFullRuleName(ruleName);
        string suffix4 = baseName + "4";
        string suffix6 = baseName + "6";
        var nftRoot = GetRules();

        foreach (var entry in nftRoot.Entries)
        {
            // must have a rule and comment
            if (string.IsNullOrWhiteSpace(entry.Rule?.Comment))
            {
                continue;
            }

            // must match our internal comment format
            Match m = commentRegex.Match(entry.Rule.Comment);
            if (!m.Success)
            {
                continue;
            }

            // must match the rule name, or one of the suffixes
            var found = m.Groups["ruleName"].Value;
            if (found.Equals(baseName, StringComparison.OrdinalIgnoreCase) ||
                found.Equals(suffix4, StringComparison.OrdinalIgnoreCase) ||
                found.Equals(suffix6, StringComparison.OrdinalIgnoreCase))
            {
                return IPBanFirewallUtility.GetPortRangeString(entry.Rule.Ports);
            }
        }
        return null;
    }

    /// <inheritdoc />
    public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
    {
        var nftRoot = GetRules();
        SortedSet<string> names = new(StringComparer.OrdinalIgnoreCase);
        string baseFilter = string.IsNullOrWhiteSpace(ruleNamePrefix) ? null : GetFullRuleName(ruleNamePrefix);

        foreach (var entry in nftRoot.Entries)
        {
            // must have a rule and comment
            if (string.IsNullOrWhiteSpace(entry.Rule?.Comment))
            {
                continue;
            }

            // must match our internal comment format
            Match m = commentRegex.Match(entry.Rule.Comment);
            if (!m.Success)
            {
                continue;
            }

            // must match the base filter if provided (exact match or with 4/6 suffix)
            var found = m.Groups["ruleName"].Value;
            if (!string.IsNullOrWhiteSpace(baseFilter))
            {
                // Accept exact base or base with 4/6 suffix
                if (!found.Equals(baseFilter, StringComparison.OrdinalIgnoreCase) &&
                    !found.Equals(baseFilter + "4", StringComparison.OrdinalIgnoreCase) &&
                    !found.Equals(baseFilter + "6", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
            }
            names.Add(found);
        }
        return names;
    }

    /// <inheritdoc />
    public override IPBanMemoryFirewall Compile()
    {
        IPBanMemoryFirewall mem = new(RulePrefix);

        foreach (var item in EnumerateAllSetIPs(null))
        {
            var ips = item.Entries.Select(ip => { _ = IPAddressRange.TryParse(ip, out var r); return r; }).Where(r => r is not null).ToList();
            var ports = item.Ports;
            if (item.Allow)
            {
                // no need to invert ports since allowed ports are never inverted in an allow call
                mem.AllowIPAddresses(item.Name, ips, ports);
            }
            else
            {
                // since ports were inverted in the original block call, we must invert them again--they will be inverted yet again inside this block call
                var invertedPorts = IPBanFirewallUtility.InvertPortRanges(ports);
                mem.BlockIPAddresses(item.Name, ips, invertedPorts);
            }
        }
        return mem;
    }

    /// <summary>
    /// Initialize
    /// </summary>
    protected virtual void Initialize()
    {
        MemoryStream ms = new();
        using (var sw = new StreamWriter(ms, ExtensionMethods.Utf8EncodingNoPrefix, leaveOpen: true))
        {
            sw.WriteLine($"destroy table inet {tableName}");
            sw.WriteLine($"add table inet {tableName}");
            sw.WriteLine($"add chain inet {tableName} {chainName} {{ type filter hook input priority -1; }}");
        }
        RunNftStream(ms, null, "-f", "-");
    }

    #endregion

    #region Helpers

    private string GetFullRuleName(string ruleNamePrefix)
    {
        var fullRuleName = ruleNamePrefix?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(fullRuleName))
        {
            return SanitizeRuleName(RulePrefix); // base prefix (unlikely used directly)
        }

        // If caller already passed a suffixed internal name (ends with 4 or 6) strip the suffix
        // so we always operate on the base name internally when computing set names.
        if (fullRuleName.Length > 1)
        {
            char last = fullRuleName[^1];
            if ((last == '4' || last == '6') && char.IsLetterOrDigit(fullRuleName[^2]))
            {
                fullRuleName = fullRuleName[..^1];
            }
        }

        if (!fullRuleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
        {
            fullRuleName = RulePrefix + fullRuleName;
        }
        return SanitizeRuleName(fullRuleName);
    }

    private static bool IsSuffixRuleName(string name) => !string.IsNullOrWhiteSpace(name) && (name.EndsWith('4') || name.EndsWith('6'));

    private static string StripSuffix(string name)
    {
        if (IsSuffixRuleName(name))
        {
            return name[..^1];
        }
        return name;
    }

    private static string SanitizeRuleName(string name) => new([.. name.Select(c => char.IsLetterOrDigit(c) ? char.ToLowerInvariant(c) : '_')]);

    private static IEnumerable<string> BuildBatches(string action, string tableName, string setName, List<IPAddressRange> elements)
    {
        const int maxElementsPerBatch = 4096;
        const int maxCharsPerLine = 16384;
        if (elements.Count == 0) yield break;
        int index = 0; var sb = new StringBuilder(1024);
        while (index < elements.Count)
        {
            sb.Append(action).Append(" element inet ").Append(tableName).Append(' ').Append(setName).Append(" { ");
            int count = 0;
            while (index < elements.Count && count < maxElementsPerBatch && sb.Length < maxCharsPerLine)
            {
                if (count > 0) sb.Append(", ");
                sb.Append(elements[index].ToCidrString(false));
                index++;
                count++;
            }
            sb.Append(" }");
            yield return sb.ToString();
            sb.Clear();
        }
    }

    private void BatchUpdateSets(string setV4, string setV6, IEnumerable<IPAddressRange> ranges)
    {
        var v4 = new List<IPAddressRange>();
        var v6 = new List<IPAddressRange>();
        foreach (var r in ranges.Where(r => r is not null).OrderBy(r => r).Combine())
        {
            if (r.Begin.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                v4.Add(r);
            }
            else
            {
                v6.Add(r);
            }
        }
        using var tmp = new TempFile();
        using (var sw = new StreamWriter(tmp, false, ExtensionMethods.Utf8EncodingNoPrefix, sixtyFourK))
        {
            // Always flush sets first so contents exactly match the provided list
            sw.WriteLine($"flush set inet {tableName} {setV4}");
            sw.WriteLine($"flush set inet {tableName} {setV6}");
            // Add new elements (if any)
            foreach (var line in BuildBatches("add", tableName, setV4, v4)
                .Concat(BuildBatches("add", tableName, setV6, v6)))
            {
                sw.WriteLine(line);
            }
        }
        RunNftFile(tmp);
    }

    private void BatchUpdateSetsDelta(string setV4, string setV6,
        IEnumerable<IPAddressRange> addsV4, IEnumerable<IPAddressRange> addsV6,
        IEnumerable<IPAddressRange> delsV4, IEnumerable<IPAddressRange> delsV6)
    {
        var add4 = addsV4.Where(r => r is not null).OrderBy(r => r).ToList();
        var add6 = addsV6.Where(r => r is not null).OrderBy(r => r).ToList();
        var del4 = delsV4.Where(r => r is not null).OrderBy(r => r).ToList();
        var del6 = delsV6.Where(r => r is not null).OrderBy(r => r).ToList();
        if (add4.Count + add6.Count + del4.Count + del6.Count == 0)
        {
            return;
        }
        using var tmp = new TempFile();
        bool wrote = false;
        using (var sw = new StreamWriter(tmp, false, ExtensionMethods.Utf8EncodingNoPrefix, sixtyFourK))
        {
            foreach (var line in BuildBatches("add", tableName, setV4, add4)
                .Concat(BuildBatches("add", tableName, setV6, add6))
                .Concat(BuildBatches("delete", tableName, setV4, del4))
                .Concat(BuildBatches("delete", tableName, setV6, del6)))
            {
                sw.WriteLine(line);
                wrote = true;
            }
        }
        if (wrote)
        {
            RunNftFile(tmp);
        }
     }

    private void EnsureRules(string ruleName, IEnumerable<PortRange> allowedPorts, bool allow)
    {
        static void CreateRuleIfNeeded(bool flag, string ruleName, bool allow, string family, string desiredPorts, List<string> rulesToCreate)
        {
            if (!flag)
            {
                return;
            }

            // allow inserts at beginning, block adds to end (allow takes precedence)
            var cmdType = allow ? "insert" : "add";
            var action = allow ? "accept" : "drop";
            if (!string.IsNullOrWhiteSpace(desiredPorts))
            {
                desiredPorts = " th dport { " + desiredPorts + "}";
            }
            var rule = $"{cmdType} rule inet {tableName} {chainName} {family} saddr @{ruleName}{desiredPorts} {action} comment \"{internalRuleCommentPrefix}{ruleName}\"";

            rulesToCreate.Add(rule);
        }

        // Read existing rules
        var nftRoot = GetRules();

        // Normalize to base rule name (unsuffixed)
        string baseRuleName = SanitizeRuleName(ruleName);

        // each rule has ipv4 and ipv6 suffixes
        string ruleName4 = baseRuleName + "4";
        string ruleName6 = baseRuleName + "6";
        bool needV4Rule = true;
        bool needV6Rule = true;

        // Determine desired ports. For block rules invert allowedPorts (block everything else). Null means all.
        string desiredPorts = string.Empty;
        if (allowedPorts is not null)
        {
            desiredPorts = (allow ? IPBanFirewallUtility.GetPortRangeStringAllow(allowedPorts) : IPBanFirewallUtility.GetPortRangeStringBlock(allowedPorts)) ?? string.Empty;
        }

        // Parse existing rules to find any current internal rules to remove (avoid duplicates).
        List<uint> deleteHandles = [];
        List<string> rulesToCreate = [];
        foreach (var entry in nftRoot.Entries)
        {
            var rule = entry.Rule;

            // must be a rule and have a comment
            if (rule?.Handle is null || string.IsNullOrWhiteSpace(rule.Comment))
            {
                continue;
            }

            // must match a rule we care about
            var m = commentRegex.Match(rule.Comment);
            if (!m.Success)
            {
                continue;
            }

            // snag rule name and see if it matches either suffix
            var found = m.Groups["ruleName"].Value;
            bool matchesV4 = found.Equals(ruleName4, StringComparison.OrdinalIgnoreCase);
            bool matchesV6 = found.Equals(ruleName6, StringComparison.OrdinalIgnoreCase);
            if (matchesV4 || matchesV6)
            {
                // grab the boolean that determines whether this rule will be created
                ref bool createRuleFlag = ref matchesV4 ? ref needV4Rule : ref needV6Rule;

                // if allow mismatch or ports mismatch, recreate the rule
                createRuleFlag = rule.Allow != allow || IPBanFirewallUtility.GetPortRangeString(rule.Ports) != desiredPorts;

                // if flag says we need to create the rule, we must delete the old one first
                if (createRuleFlag)
                {
                    // mark for deletion
                    Logger.Debug("Deleting existing nftables rule {0} (handle {1}) to be replaced", rule.Comment, rule.Handle.Value);
                    deleteHandles.Add(rule.Handle.Value);
                }
                else
                {
                    Logger.Trace("Keeping existing nftables rule {0} (handle {1})", rule.Comment, rule.Handle.Value);
                }
            }
        }

        // If we still need rules, add them
        CreateRuleIfNeeded(needV4Rule, ruleName4, allow, "ip", desiredPorts, rulesToCreate);
        CreateRuleIfNeeded(needV6Rule, ruleName6, allow, "ip6", desiredPorts, rulesToCreate);

        MemoryStream ms = new();
        using (var sw = new StreamWriter(ms, ExtensionMethods.Utf8EncodingNoPrefix, leaveOpen: true))
        {
            // if we have any delete handles, do those first
            if (deleteHandles.Count != 0)
            {
                // Delete existing internal rules (descending handles safest)
                deleteHandles.Sort((a, b) => b.CompareTo(a));
                foreach (var handle in deleteHandles)
                {
                    sw.WriteLine($"delete rule inet {tableName} {chainName} handle {handle}");
                }
            }
            foreach (var rule in rulesToCreate)
            {
                sw.WriteLine(rule);
            }
        }
        if (ms.Length != 0)
        {
            RunNftStream(ms, null, "-f", "-");
        }
    }

    private void RemoveRule(string fullRuleName)
    {
        var nftRoot = GetRules();
        string suffixed4 = fullRuleName + "4";
        string suffixed6 = fullRuleName + "6";
        List<uint> handles = [];

        foreach (var entry in nftRoot.Entries)
        {
            // must have a rule and comment
            if (string.IsNullOrWhiteSpace(entry.Rule?.Comment))
            {
                continue;
            }

            // must match our internal comment format
            Match m = commentRegex.Match(entry.Rule.Comment);
            if (!m.Success)
            {
                continue;
            }
            var foundRuleName = m.Groups["ruleName"].Value;
            if (foundRuleName == fullRuleName || foundRuleName == suffixed4 || foundRuleName == suffixed6)
            {
                if (entry.Rule.Handle.HasValue)
                {
                    handles.Add(entry.Rule.Handle.Value);
                }
            }
        }
        if (handles.Count == 0)
        {
            return; // nothing to delete
        }

        // Delete highest handles first just in case the kernel processes sequentially and renumbers (defensive)
        handles.Sort((a, b) => b.CompareTo(a));
        MemoryStream ms = new();
        using (var sw = new StreamWriter(ms, ExtensionMethods.Utf8EncodingNoPrefix, leaveOpen: true))
        {
            foreach (var h in handles)
            {
                sw.WriteLine($"delete rule inet {tableName} {chainName} handle {h}");
            }
        }
        RunNftStream(ms, null, "-f", "-");
    }

    private void RemoveSet(string fullRuleName)
    {
        var set4 = fullRuleName + "4";
        var set6 = fullRuleName + "6";
        MemoryStream ms = new();
        using (var sw = new StreamWriter(ms, ExtensionMethods.Utf8EncodingNoPrefix, leaveOpen: true))
        {
            sw.WriteLine($"delete set inet {tableName} {set4}");
            sw.WriteLine($"delete set inet {tableName} {set6}");
        }
        RunNftStream(ms, null, "-f", "-");
    }

    private IEnumerable<NftRuleInternal> EnumerateAllSetIPs(bool? allow, string ruleNamePrefix = null)
    {
        var nftRoot = GetRulesAndSets();
        string baseFilter = string.IsNullOrWhiteSpace(ruleNamePrefix) ? null : GetFullRuleName(ruleNamePrefix);

        foreach (var entry in nftRoot?.Entries)
        {
            var set = entry.Set;
            if (string.IsNullOrWhiteSpace(set?.Name))
            {
                continue; // not a set entry
            }

            // find first referencing rule (built during deserialization)
            var referencingRule = set.ReferencingRules.FirstOrDefault();
            if (referencingRule is null)
            {
                continue; // without a rule we cannot determine allow / block reliably
            }

            // filter on allow flag if requested using the rule verdict, NOT set comment
            if (allow.HasValue && referencingRule.Allow != allow.Value)
            {
                continue;
            }

            // optional name filter (strip v4/v6 suffix)
            if (!string.IsNullOrWhiteSpace(baseFilter) && !StripSuffix(set.Name).Equals(baseFilter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var elements = set.EnumerateSetElements().ToList();
            IReadOnlyCollection<PortRange> ports = referencingRule.Ports ?? [];
            yield return new NftRuleInternal(set.Name, referencingRule.Allow, ports, elements);
        }
    }

    private void EnsureSets(params string[] typesAndNames)
    {
        MemoryStream ms = new();
        using (var sw = new StreamWriter(ms, ExtensionMethods.Utf8EncodingNoPrefix, sixtyFourK, leaveOpen: true))
        {
            for (var i = 0; i < typesAndNames.Length - 1; i += 2)
            {
                var name = typesAndNames[i];
                var type = typesAndNames[i + 1];
                sw.WriteLine($"add set inet {tableName} {name} {{ type {type}; flags interval; }}");
            }
        }
        RunNftStream(ms, null, "-f", "-");
    }

    #endregion

    #region Nft helpers

#if USE_NFT_NATIVE

    private int RunNft(params IEnumerable<string> args)
    {
        var cmd = string.Join(' ', args);
        var cmdBytes = ExtensionMethods.Utf8EncodingNoPrefix.GetBytes(cmd);
        Array.Resize(ref cmdBytes, cmdBytes.Length + 1);
        cmdBytes[^1] = 0; // null terminate
        var rc = nftCtx.Run(cmdBytes, out _, out var se);
        if (se.Length != 0)
        {
            Logger.Debug($"{nameof(RunNft)} stderr: {0}", ExtensionMethods.Utf8EncodingNoPrefix.GetString(se));
        }
        return rc;
    }

    private int RunNftFile(string fileName)
    {
        int rc = nftCtx.RunFile(fileName, out _, out var se);
        if (se.Length != 0)
        {
            Logger.Debug($"{nameof(RunNftFile)} stderr: {0}", ExtensionMethods.Utf8EncodingNoPrefix.GetString(se));
        }
        return rc;
    }

    private int RunNftStream(MemoryStream inputStream, Stream outputStream, params IEnumerable<string> args)
    {
        // if no input and args, use args as input
        if ((inputStream is null || inputStream.Length == 0) && args.Any())
        {
            // if user is asking for json, we can skip since native doesn't need this switch
            if (args.First() == "-j")
            {
                args = args.Skip(1);
            }

            // use args as the command
            var argsText = string.Join(' ', args);

            // -f - means read from stdin, so don't write args to input stream
            if (argsText != "-f -")
            {
                inputStream ??= new MemoryStream();
                inputStream.Write(ExtensionMethods.Utf8EncodingNoPrefix.GetBytes(argsText));
            }
        }

        // need a command or we're done
        if (inputStream is null || inputStream.Length == 0)
        {
            throw new ArgumentException($"No input provided to {nameof(RunNftStream)}");
        }

        inputStream.WriteByte(0); // null terminate
        var rc = nftCtx.Run(inputStream.ToArray(), out var stdout, out var stderr);

        if (outputStream is not null && outputStream.CanWrite && stdout is not null)
        {
            outputStream.Write(stdout);
            if (outputStream.CanSeek)
            {
                outputStream.Position = 0;
            }
        }

        if (stderr is not null && stderr.Length != 0)
        {
            Logger.Debug($"{nameof(RunNftStream)} stderr: {0}", ExtensionMethods.Utf8EncodingNoPrefix.GetString(stderr));
        }

        return rc;
    }

#else

    private static int RunNft(params IEnumerable<string> args)
    {
        return IPBanFirewallUtility.RunProcess("nft", null, null, args);
    }

    private static int RunNftFile(string fileName)
    {
        return IPBanFirewallUtility.RunProcess("nft", null, null, "-f", fileName);
    }

    private static int RunNftStream(MemoryStream inputStream, Stream outputStream, params IEnumerable<string> args)
    {
        if (inputStream is not null && inputStream.CanSeek)
        {
            inputStream.Position = 0;
        }
        var exitCode = IPBanFirewallUtility.RunProcess("nft", inputStream, outputStream, args);
        if (outputStream is not null && outputStream.CanSeek)
        {
            outputStream.Position = 0;
        }
        return exitCode;
    }

#endif
    private NetFilterRuleset GetRules()
    {
        MemoryStream ms = new();
        RunNftStream(null, ms, "-j", "list", "chain", "inet", tableName, chainName);
        var nftRoot = JsonSerializationHelper.Deserialize<NetFilterRuleset>(ms);
        return nftRoot;
    }

    private NetFilterRuleset GetRulesAndSets()
    {
        using TempFile tmp = new();
        using var fs = File.Open(tmp.FullName, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        RunNftStream(null, fs, "-j", "list", "table", "inet", tableName);
        var nftRoot = JsonSerializationHelper.Deserialize<NetFilterRuleset>(fs);
        return nftRoot;
    }

#endregion
}

#pragma warning restore SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.
#pragma warning restore SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time
#pragma warning restore IDE1006 // Naming Styles