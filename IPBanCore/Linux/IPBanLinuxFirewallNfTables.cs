using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.

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
        using var tmpFile = RunNftCaptureFile("-j", "list", "chain", "inet", tableName, chainName);

        // Normalize to base rule name (unsuffixed)
        string baseName = GetFullRuleName(ruleName);
        string suffix4 = baseName + "4";
        string suffix6 = baseName + "6";

        var nftRoot = JsonSerializationHelper.DeserializeFromFile<NetFilterRuleset>(tmpFile);
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
        using var tmpFile = RunNftCaptureFile("-j", "list", "chain", "inet", tableName, chainName);
        var nftRoot = JsonSerializationHelper.DeserializeFromFile<NetFilterRuleset>(tmpFile);
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
        StringWriter sw = new();
        sw.WriteLine($"destroy table inet {tableName}");
        sw.WriteLine($"add table inet {tableName}");
        sw.WriteLine($"add chain inet {tableName} {chainName} {{ type filter hook input priority -1; }}");
        if (sw.GetStringBuilder().Length != 0)
        {
            using var tmp = new TempFile();
            File.WriteAllText(tmp, sw.ToString(), ExtensionMethods.Utf8EncodingNoPrefix);
            RunNft("-f", tmp);
        }
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

    private static void BatchUpdateSets(string setV4, string setV6, IEnumerable<IPAddressRange> ranges)
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
        bool wrote = false;
        using (var sw = new StreamWriter(tmp, false, ExtensionMethods.Utf8EncodingNoPrefix, sixtyFourK))
        {
            // Always flush sets first so contents exactly match the provided list
            sw.WriteLine($"flush set inet {tableName} {setV4}");
            sw.WriteLine($"flush set inet {tableName} {setV6}");
            wrote = true;

            // Add new elements (if any)
            foreach (var line in BuildBatches("add", tableName, setV4, v4)
                .Concat(BuildBatches("add", tableName, setV6, v6)))
            {
                sw.WriteLine(line);
            }
        }
        if (wrote)
        {
            RunNft("-f", tmp);
        }
    }

    private static void BatchUpdateSetsDelta(string setV4, string setV6,
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
            RunNft("-f", tmp);
        }
    }

    private static void EnsureRules(string ruleName, IEnumerable<PortRange> allowedPorts, bool allow)
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
        using var tempFile = RunNftCaptureFile("-j", "list", "chain", "inet", tableName, chainName);
        var nftRoot = JsonSerializationHelper.DeserializeFromFile<NetFilterRuleset>(tempFile);

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

        using var batch = new TempFile();
        var wrote = false;
        using (var sw = new StreamWriter(batch, false, ExtensionMethods.Utf8EncodingNoPrefix))
        {
            // if we have any delete handles, do those first
            if (deleteHandles.Count != 0)
            {
                // Delete existing internal rules (descending handles safest)
                deleteHandles.Sort((a, b) => b.CompareTo(a));
                foreach (var handle in deleteHandles)
                {
                    wrote = true;
                    sw.WriteLine($"delete rule inet {tableName} {chainName} handle {handle}");
                }
            }
            foreach (var rule in rulesToCreate)
            {
                wrote = true;
                sw.WriteLine(rule);
            }
        }
        if (wrote)
        {
            RunNft("-f", batch);
        }
    }

    private static void RemoveRule(string fullRuleName)
    {
        // fullRuleName here is base (unsuffixed). Delete any matching suffixed internal rules in a single batch.
        using var tmpFile = RunNftCaptureFile("-j", "list", "chain", "inet", tableName, chainName);

        string suffixed4 = fullRuleName + "4";
        string suffixed6 = fullRuleName + "6";

        var nftRoot = JsonSerializationHelper.DeserializeFromFile<NetFilterRuleset>(tmpFile);
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
        using var tmp = new TempFile();
        using (var sw = new StreamWriter(tmp, false, ExtensionMethods.Utf8EncodingNoPrefix))
        {
            foreach (var h in handles)
            {
                sw.WriteLine($"delete rule inet {tableName} {chainName} handle {h}");
            }
        }
        RunNft("-f", tmp);
    }

    private static void RemoveSet(string fullRuleName)
    {
        var set4 = fullRuleName + "4";
        var set6 = fullRuleName + "6";
        using var tmp = new TempFile();
        using (var sw = new StreamWriter(tmp, false, ExtensionMethods.Utf8EncodingNoPrefix))
        {
            sw.WriteLine($"delete set inet {tableName} {set4}");
            sw.WriteLine($"delete set inet {tableName} {set6}");
        }
        RunNft("-f", tmp);
    }

    private IEnumerable<NftRuleInternal> EnumerateAllSetIPs(bool? allow, string ruleNamePrefix = null)
    {
        using var tempFile = RunNftCaptureFile("-j", "list", "table", "inet", tableName);

        var nftRoot = JsonSerializationHelper.DeserializeFromFile<NetFilterRuleset>(tempFile);
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

    private static void EnsureSets(params string[] typesAndNames)
    {
        StringWriter sw = new();
        for (var i = 0; i < typesAndNames.Length - 1; i += 2)
        {
            var name = typesAndNames[i];
            var type = typesAndNames[i + 1];
            sw.WriteLine($"add set inet {tableName} {name} {{ type {type}; flags interval; }}");
        }
        using var tmp = new TempFile();
        File.WriteAllText(tmp, sw.ToString(), ExtensionMethods.Utf8EncodingNoPrefix);
        RunNft("-f", tmp);
    }

    #endregion

    #region Nft helpers

    private static int RunNft(params string[] args)
    {

#if DEBUG

        if (args.Length > 1 && args[0] == "-f")
        {
            Logger.Debug("Running nft with temp file text: {0}", File.ReadAllText(args[1]));
        }

#endif

        return IPBanFirewallUtility.RunProcess("nft", null, null, args);
    }

    private static TempFile RunNftCaptureFile(params string[] args)
    {
        var tmp = new TempFile();
        var exitCode = IPBanFirewallUtility.RunProcess("nft", null, tmp, args);
        if (!File.Exists(tmp))
        {
            Logger.Warn("Nftables capture failed with exit code {0}", exitCode);
            tmp.Dispose();
            return null;
        }

#if DEBUG

        Logger.Debug("Nft capture file contents: {0}", File.ReadAllText(tmp));

#endif

        return tmp;
    }

    #endregion
}

#pragma warning restore SYSLIB1045 // Convert to 'GeneratedRegexAttribute'.