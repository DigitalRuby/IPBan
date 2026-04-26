using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace DigitalRuby.IPBanCore;

#nullable enable

/// <summary>
/// Drop-in migrator for: DigitalRuby.IPBan*, DigitalRuby.IPBanProDatacenter, DigitalRuby.IPBanProPersonal
/// Usage example once wired into your CLI:
/// DigitalRuby.IPBan migrate f2b --root /etc/fail2ban --out ./ipban.migrated.config
/// Notes:
/// - Translates fail2ban macros (&lt;HOST&gt;, &lt;IP&gt;, etc.) to IPBan format.
/// - No GPL regex embedding beyond copying configuration text users already possess.
/// - Generates bash hook framework into the chosen hook directory (default current dir).
/// </summary>
public static class MigrateFail2Ban
{
    private static bool _strictMode;
    private static int _warningCount;
    private static int _errorCount;

    /// <summary>
    /// Check if this is a fail2ban migration, and if so, run it
    /// </summary>
    /// <param name="args">Args</param>
    /// <returns>-1 if not a fail2ban migration, otherwise exit code</returns>
    public static int RunFromArgs(string[] args)
    {
        // Basic subcommand router pattern:
        // ipban migrate f2b [options]
        if (args.Length == 0 || args[0] != "f2b")
        {
            // Not our command; indicate not handled
            return -1;
        }
        var opts = Options.Parse([.. args.Skip(1)]);
        if (opts.ShowHelp)
        {
            Console.WriteLine(Options.HelpText);
            return 0;
        }

        try
        {
            return Run(opts);
        }
        catch (Exception ex)
        {
            Logger.Error("Migration failed", ex);
            return 2;
        }
    }

    private static int Run(Options o)
    {
        _strictMode = o.Strict;
        _warningCount = 0;
        _errorCount = 0;

        // Validate root directory exists
        if (!Directory.Exists(o.Root))
        {
            Error($"Fail2ban root directory does not exist: {o.Root}");
            return 1;
        }

        // 1) Read fail2ban jails (merged)
        var reader = new F2BReader(o.Root);
        var jails = reader.ReadJails(includeDisabled: o.IncludeDisabled);
        if (jails.Count == 0)
        {
            Error("No enabled jails found (use --include-disabled to see all).");
            if (_strictMode)
            {
                return 1;
            }
        }

        // 2) For each jail, read filter failregex and translate
        var compiled = new List<MigratedJail>();
        foreach (var jail in jails)
        {
            if (!o.IncludeDisabled && !jail.Enabled)
            {
                continue;
            }
            if (string.IsNullOrWhiteSpace(jail.Filter))
            {
                Warn($"Jail '{jail.Name}' has no filter, skipping.");
                continue;
            }
            if (jail.LogPaths.Count == 0)
            {
                Warn($"Jail '{jail.Name}' has no logpath, skipping.");
                continue;
            }

            // Look for filter file (.conf and .local)
            var filterConfPath = Path.Combine(o.Root, "filter.d", $"{jail.Filter}.conf");
            var filterLocalPath = Path.Combine(o.Root, "filter.d", $"{jail.Filter}.local");

            F2BFilter? filter = null;

            if (File.Exists(filterConfPath))
            {
                filter = reader.ReadFilter(filterConfPath);
            }

            // Merge .local file on top if it exists
            if (File.Exists(filterLocalPath))
            {
                var localFilter = reader.ReadFilter(filterLocalPath);
                if (filter is null)
                {
                    filter = localFilter;
                }
                else
                {
                    // Merge: .local overrides/extends .conf
                    foreach (var regex in localFilter.FailRegex)
                    {
                        if (!filter.FailRegex.Contains(regex))
                        {
                            filter.FailRegex.Add(regex);
                        }
                    }
                    // Merge definitions
                    foreach (var kvp in localFilter.Definitions)
                    {
                        filter.Definitions[kvp.Key] = kvp.Value;
                    }
                }
            }

            if (filter is null)
            {
                Warn($"Filter file missing for jail '{jail.Name}': {filterConfPath}, skipping.");
                continue;
            }

            if (filter.FailRegex.Count == 0)
            {
                Warn($"Filter '{filter.Name}' has no failregex lines, skipping jail '{jail.Name}'.");
                continue;
            }

            // Expand fail2ban macros to IPBan format
            var expandedRegexes = new List<string>();
            foreach (var regex in filter.FailRegex)
            {
                var expanded = ExpandFail2BanMacros(regex, filter.Definitions);
                expanded = IPBanRegexMacros.Expand(expanded);
                expandedRegexes.Add(expanded);
            }

            var alternation = CombineAlternation(expandedRegexes);

            // Validate that the regex contains ipaddress capture group
            if (!ContainsIpAddressGroup(alternation))
            {
                Warn($"Jail '{jail.Name}' regex does not contain an 'ipaddress' capture group. The regex may not work correctly.");
            }

            compiled.Add(new MigratedJail
            {
                Name = jail.Name,
                Source = SanitizeSource(jail.Name),
                FailedLoginThreshold = jail.MaxRetry,
                LogPaths = [.. jail.LogPaths],
                FailedLoginRegex = alternation
            });
        }

        // Check for strict mode failures
        if (_strictMode && (_warningCount > 0 || _errorCount > 0))
        {
            Logger.Error($"Strict mode: {_errorCount} error(s), {_warningCount} warning(s). Aborting.");
            return 1;
        }

        if (compiled.Count == 0)
        {
            Error("No jails were successfully migrated.");
            return 1;
        }

        // 3) Choose global BanTime/FindTime (minimum across jails; defaults if none)
        var (banSecs, findSecs) = ComputeGlobalTimes(jails, o.DefaultBanSecs, o.DefaultFindSecs);
        var banTime = FormatDuration(banSecs);
        var findTime = FormatDuration(findSecs);

        if (o.DryRun)
        {
            Logger.Info("=== DRY RUN (no files written) ===");
            Logger.Info($"Jails migrated: {compiled.Count}");
            foreach (var j in compiled.OrderBy(j => j.Source))
            {
                Logger.Info($"- {j.Source}: paths={j.LogPaths.Count}, threshold={(j.FailedLoginThreshold?.ToString() ?? "(default)")}");
            }
            Logger.Info($"Global BanTime: {banTime}, MinBetweenFailures: {findTime}");
            return 0;
        }

        var outDir = Path.GetDirectoryName(Path.GetFullPath(o.Out));
        if (!string.IsNullOrEmpty(outDir))
        {
            Directory.CreateDirectory(outDir);
        }

        // 4) Write ipban.migrated.config
        WriteIpBanConfig(o.Out, compiled, banTime, findTime, o.BanHookPath, o.UnbanHookPath);

        // 5) Write hook framework into o.HookDir
        var scaffold = new HookScaffolder(o.HookDir);
        scaffold.WriteAll([.. compiled.Select(j => j.Source).Distinct().OrderBy(s => s)]);

        Logger.Info($"Wrote IPBan config: {o.Out}");
        Logger.Info($"Hook dir: {o.HookDir}");
        Logger.Info($"Successfully migrated {compiled.Count} jail(s).");
        if (_warningCount > 0)
        {
            Logger.Warn($"{_warningCount} warning(s) occurred during migration.");
        }
        Logger.Info("Done.");
        return 0;
    }

    #region Utilities & helpers

    private static void Warn(string msg)
    {
        _warningCount++;
        Logger.Warn(msg);
    }

    private static void Error(string msg)
    {
        _errorCount++;
        Logger.Error(msg);
    }

    /// <summary>
    /// Check if regex contains an ipaddress capture group
    /// </summary>
    private static bool ContainsIpAddressGroup(string regex)
    {
        // Look for (?<ipaddress> or (?P<ipaddress> patterns
        return Regex.IsMatch(regex, @"\(\?(?:P)?<ipaddress>", RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// Expand fail2ban-specific macros that aren't handled by IPBanRegexMacros
    /// </summary>
    private static string ExpandFail2BanMacros(string pattern, Dictionary<string, string> definitions)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return pattern ?? string.Empty;
        }

        var result = pattern;

        // Expand definition references like %(name)s
        var maxIterations = 10; // Prevent infinite loops
        for (int i = 0; i < maxIterations; i++)
        {
            var before = result;
            foreach (var kvp in definitions)
            {
                result = result.Replace($"%({kvp.Key})s", kvp.Value, StringComparison.OrdinalIgnoreCase);
            }
            if (result == before)
            {
                break;
            }
        }

        // Common fail2ban macros
        result = result.Replace("<F-ID>", "(?<id>", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("</F-ID>", ")", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("<F-MLFID>", "(?:", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("</F-MLFID>", ")", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("<F-NOFAIL>", "(?:", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("</F-NOFAIL>", ")?", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("<F-CONTENT>", "(?<content>", StringComparison.OrdinalIgnoreCase);
        result = result.Replace("</F-CONTENT>", ")", StringComparison.OrdinalIgnoreCase);

        // Remove fail2ban-specific tags that don't translate
        result = Regex.Replace(result, @"<F-[A-Z_]+/>", "", RegexOptions.IgnoreCase);

        return result;
    }

    private static (int banSecs, int findSecs) ComputeGlobalTimes(
        IList<F2BJail> jails, int defaultBanSecs, int defaultFindSecs)
    {
        int ban = defaultBanSecs;
        int find = defaultFindSecs;

        foreach (var j in jails.Where(j => j.Enabled))
        {
            if (j.BanTimeSecs.HasValue && j.BanTimeSecs.Value > 0)
            {
                ban = Math.Min(ban, j.BanTimeSecs.Value);
            }
            if (j.FindTimeSecs.HasValue && j.FindTimeSecs.Value > 0)
            {
                find = Math.Min(find, j.FindTimeSecs.Value);
            }
        }
        return (ban, find);
    }

    private static string CombineAlternation(IEnumerable<string> patterns)
    {
        var sb = new StringBuilder();
        bool first = true;
        foreach (var p in patterns)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            if (!first) sb.Append('|');
            sb.Append("(?:").Append(p.Trim()).Append(')');
            first = false;
        }
        return sb.ToString();
    }

    private static string SanitizeSource(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (char.IsLetterOrDigit(ch) || ch == '_' || ch == '.' || ch == ':' || ch == '-')
            {
                sb.Append(ch);
            }
            else
            {
                sb.Append('-');
            }
        }
        return sb.ToString();
    }

    private static string FormatDuration(int seconds)
    {
        // IPBan format: dd:hh:mm:ss (two-digit components)
        if (seconds < 0) seconds = 0;
        int d = seconds / 86400; seconds %= 86400;
        int h = seconds / 3600; seconds %= 3600;
        int m = seconds / 60; int s = seconds % 60;
        return $"{d:00}:{h:00}:{m:00}:{s:00}";
    }

    private static void WriteIpBanConfig(
        string outPath,
        IList<MigratedJail> jails,
        string banTime,
        string minBetweenFailures,
        string processOnBan,
        string processOnUnban)
    {
        var doc = new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            new XComment(" Migrated from fail2ban - review and adjust as needed "),
            new XElement("configuration",
                new XElement("LogFilesToParse",
                    new XElement("LogFiles",
                        jails.Select(j =>
                            new XElement("LogFile",
                                new XElement("Source", j.Source),
                                new XElement("PathAndMask", string.Join("\n", j.LogPaths)),
                                new XElement("FailedLoginRegex", new XCData("\n" + j.FailedLoginRegex + "\n")),
                                new XElement("SuccessfulLoginRegex"),
                                new XElement("PlatformRegex", "Linux"),
                                new XElement("PingInterval", "10000"),
                                new XElement("MaxFileSize", "16777216"),
                                new XElement("FailedLoginThreshold", j.FailedLoginThreshold?.ToString() ?? "0")
                            )
                        )
                    )
                ),
                new XElement("appSettings",
                    new XElement("add", new XAttribute("key", "FailedLoginAttemptsBeforeBan"),
                                        new XAttribute("value", "5")),
                    new XElement("add", new XAttribute("key", "BanTime"),
                                        new XAttribute("value", banTime)),
                    new XElement("add", new XAttribute("key", "MinimumTimeBetweenFailedLoginAttempts"),
                                        new XAttribute("value", minBetweenFailures)),
                    new XElement("add", new XAttribute("key", "ExpireTime"),
                                        new XAttribute("value", banTime)),
                    !string.IsNullOrWhiteSpace(processOnBan)
                        ? new XElement("add", new XAttribute("key", "ProcessToRunOnBan"),
                                              new XAttribute("value", $"{processOnBan}|###IPADDRESS### ###SOURCE### ###USERNAME### ###COUNT###"))
                        : null,
                    !string.IsNullOrWhiteSpace(processOnUnban)
                        ? new XElement("add", new XAttribute("key", "ProcessToRunOnUnban"),
                                              new XAttribute("value", $"{processOnUnban}|###IPADDRESS### ###SOURCE###"))
                        : null
                )
            )
        );

        var settings = new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false) };
        using var fs = File.Create(outPath);
        using var xw = XmlWriter.Create(fs, settings);
        doc.Save(xw);
    }

    #endregion
}

#region Options & Models

internal sealed class Options
{
    public string Root { get; private set; } = "/etc/fail2ban";
    public string Out { get; private set; } = "./ipban.migrated.config";
    public string HookDir { get; private set; } = Directory.GetCurrentDirectory();
    public string BanHookPath => Path.Combine(HookDir, "ipban-ban-hook.sh");
    public string UnbanHookPath => Path.Combine(HookDir, "ipban-unban-hook.sh");

    public bool ShowHelp { get; private set; }
    public bool DryRun { get; private set; }
    public bool Strict { get; private set; }
    public bool IncludeDisabled { get; private set; }

    public int DefaultBanSecs { get; private set; } = 3600;   // 1h
    public int DefaultFindSecs { get; private set; } = 600;   // 10m

    public static readonly string HelpText =
@"Usage: DigitalRuby.IPBan migrate f2b [options]

Options:
  -r, --root DIR          Fail2ban root (default: /etc/fail2ban)
  -o, --out FILE          Output ipban config (default: ./ipban.migrated.config)
  --hook-dir DIR          Directory for hooks and actions (default: .)
  --include-disabled      Include disabled jails (commented suggestions in actions.conf)
  --dry-run               Dry run; do not write files
  --strict                Treat warnings as errors
  -h, --help              Show this help
";

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string? next() => (i + 1 < args.Length) ? args[++i] : null;

            switch (a.ToLowerInvariant())
            {
                case "-r":
                case "--root": o.Root = next() ?? o.Root; break;
                case "-o":
                case "--out": o.Out = next() ?? o.Out; break;
                case "--hook-dir": o.HookDir = next() ?? o.HookDir; break;
                case "--include-disabled": o.IncludeDisabled = true; break;
                case "--what-if": case "--dry-run": o.DryRun = true; break;
                case "--strict": o.Strict = true; break;
                case "-h":
                case "--help": o.ShowHelp = true; break;
                default:
                    // ignore unknowns for forward compat
                    break;
            }
        }
        return o;
    }
}

internal sealed class F2BJail
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public string? Filter { get; set; }
    public List<string> LogPaths { get; } = [];
    public int? MaxRetry { get; set; }
    public int? FindTimeSecs { get; set; }
    public int? BanTimeSecs { get; set; }
}

internal sealed class F2BFilter
{
    public string Name { get; set; } = "";
    public List<string> FailRegex { get; } = [];
    public Dictionary<string, string> Definitions { get; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class MigratedJail
{
    public string Name { get; set; } = "";
    public string Source { get; set; } = "";
    public int? FailedLoginThreshold { get; set; }
    public List<string> LogPaths { get; set; } = [];
    public string FailedLoginRegex { get; set; } = "";
}

#endregion

#region Reader & Parser

internal sealed class F2BReader
{
    public string Root { get; }

    public F2BReader(string root)
    {
        Root = root;
    }

    public List<F2BJail> ReadJails(bool includeDisabled)
    {
        var files = GatherJailFiles();
        var merged = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        var globalDefaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            foreach (var (section, key, value) in EmitKeyValues(file))
            {
                // Handle DEFAULT section for global defaults
                if (section.Equals("DEFAULT", StringComparison.OrdinalIgnoreCase))
                {
                    var cleanKey = key.TrimEnd('+').Trim();
                    if (key.EndsWith("+", StringComparison.Ordinal) || key.Contains("+=", StringComparison.Ordinal))
                    {
                        globalDefaults.TryGetValue(cleanKey, out var prev);
                        globalDefaults[cleanKey] = string.IsNullOrEmpty(prev) ? value : (prev + " " + value);
                    }
                    else
                    {
                        globalDefaults[cleanKey] = value;
                    }
                    continue;
                }

                if (!merged.TryGetValue(section, out var dict))
                {
                    dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    merged[section] = dict;
                }

                // Handle append syntax (key += value or key+= value)
                var keyTrimmed = key.Trim();
                bool isAppend = keyTrimmed.EndsWith("+", StringComparison.Ordinal);
                var baseKey = isAppend ? keyTrimmed.TrimEnd('+').Trim() : keyTrimmed;

                if (isAppend)
                {
                    dict.TryGetValue(baseKey, out var prev);
                    dict[baseKey] = string.IsNullOrEmpty(prev) ? value : (prev + " " + value);
                }
                else
                {
                    dict[baseKey] = value;
                }
            }
        }

        var jails = new List<F2BJail>();
        foreach (var kvp in merged)
        {
            var jailName = kvp.Key;
            var dict = kvp.Value;

            var jail = new F2BJail { Name = jailName };

            // Apply global defaults first, then override with jail-specific values
            if (globalDefaults.TryGetValue("enabled", out var defaultEnabled) && !dict.ContainsKey("enabled"))
            {
                dict["enabled"] = defaultEnabled;
            }
            if (globalDefaults.TryGetValue("maxretry", out var defaultMaxRetry) && !dict.ContainsKey("maxretry"))
            {
                dict["maxretry"] = defaultMaxRetry;
            }
            if (globalDefaults.TryGetValue("findtime", out var defaultFindTime) && !dict.ContainsKey("findtime"))
            {
                dict["findtime"] = defaultFindTime;
            }
            if (globalDefaults.TryGetValue("bantime", out var defaultBanTime) && !dict.ContainsKey("bantime"))
            {
                dict["bantime"] = defaultBanTime;
            }

            if (dict.TryGetValue("enabled", out var enabledStr))
            {
                jail.Enabled = ParseBool(enabledStr);
            }
            else
            {
                // Fail2ban default is often false unless specified; keep conservative
                jail.Enabled = false;
            }

            if (dict.TryGetValue("filter", out var filter))
            {
                // Filter can have parameters like "filter = myfilter[mode=aggressive]"
                var filterParts = filter.Split('[');
                jail.Filter = filterParts[0].Trim();
            }
            else
            {
                // Default filter name is same as jail name
                jail.Filter = jailName;
            }

            if (dict.TryGetValue("logpath", out var logpath))
            {
                foreach (var p in SplitLogPaths(logpath))
                {
                    if (!string.IsNullOrWhiteSpace(p) && !jail.LogPaths.Contains(p))
                    {
                        jail.LogPaths.Add(p);
                    }
                }
            }

            if (dict.TryGetValue("maxretry", out var maxRetryStr) && int.TryParse(maxRetryStr.Trim(), out var mr))
            {
                jail.MaxRetry = mr;
            }

            if (dict.TryGetValue("findtime", out var findStr))
            {
                jail.FindTimeSecs = ParseDurationToSeconds(findStr);
            }

            if (dict.TryGetValue("bantime", out var banStr))
            {
                jail.BanTimeSecs = ParseDurationToSeconds(banStr);
            }

            if (jail.Enabled || includeDisabled)
            {
                jails.Add(jail);
            }
        }

        return jails;
    }

    public F2BFilter ReadFilter(string path)
    {
        var filter = new F2BFilter { Name = Path.GetFileNameWithoutExtension(path) };

        string? currentSection = null;
        foreach (var line in ReadAllLinesMerged(path))
        {
            if (IsCommentOrBlank(line)) continue;
            if (IsSection(line, out var sec))
            {
                currentSection = sec.ToUpperInvariant();
                continue;
            }

            if (!TrySplitKeyValue(line, out var key, out var value))
            {
                continue;
            }

            var keyTrimmed = key.Trim();
            var keyLower = keyTrimmed.ToLowerInvariant();
            var valueTrimmed = value.Trim();

            // Handle DEFINITION section
            if ("DEFINITION".Equals(currentSection, StringComparison.Ordinal))
            {
                // Check for failregex (with possible append)
                if (keyLower == "failregex" || keyLower.StartsWith("failregex", StringComparison.Ordinal))
                {
                    // Handle multi-line failregex that starts with | or is just value
                    var v = valueTrimmed;
                    if (v.StartsWith("|", StringComparison.Ordinal))
                    {
                        v = v.TrimStart('|').Trim();
                    }

                    // Split on newlines or | for multiple patterns
                    var patterns = v.Split(new[] { '\n', '|' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var pattern in patterns)
                    {
                        var trimmedPattern = pattern.Trim();
                        if (!string.IsNullOrWhiteSpace(trimmedPattern))
                        {
                            filter.FailRegex.Add(trimmedPattern);
                        }
                    }
                }
                else if (!keyLower.StartsWith("ignoreregex", StringComparison.Ordinal))
                {
                    // Store other definitions for macro expansion
                    bool isAppend = keyTrimmed.EndsWith("+", StringComparison.Ordinal);
                    var baseKey = isAppend ? keyTrimmed.TrimEnd('+').Trim() : keyTrimmed;

                    if (isAppend)
                    {
                        filter.Definitions.TryGetValue(baseKey, out var prev);
                        filter.Definitions[baseKey] = string.IsNullOrEmpty(prev) ? valueTrimmed : (prev + valueTrimmed);
                    }
                    else
                    {
                        filter.Definitions[baseKey] = valueTrimmed;
                    }
                }
            }
            // Handle Init section for default definitions
            else if ("INIT".Equals(currentSection, StringComparison.Ordinal) ||
                     "DEFAULT".Equals(currentSection, StringComparison.Ordinal))
            {
                bool isAppend = keyTrimmed.EndsWith("+", StringComparison.Ordinal);
                var baseKey = isAppend ? keyTrimmed.TrimEnd('+').Trim() : keyTrimmed;

                if (isAppend)
                {
                    filter.Definitions.TryGetValue(baseKey, out var prev);
                    filter.Definitions[baseKey] = string.IsNullOrEmpty(prev) ? valueTrimmed : (prev + valueTrimmed);
                }
                else if (!filter.Definitions.ContainsKey(baseKey))
                {
                    filter.Definitions[baseKey] = valueTrimmed;
                }
            }
        }

        return filter;
    }

    private IEnumerable<string> GatherJailFiles()
    {
        var list = new List<string>(8);
        var jailConf = Path.Combine(Root, "jail.conf");
        if (File.Exists(jailConf)) list.Add(jailConf);

        var jailD = Path.Combine(Root, "jail.d");
        if (Directory.Exists(jailD))
        {
            list.AddRange(Directory.GetFiles(jailD, "*.conf", SearchOption.TopDirectoryOnly).OrderBy(s => s));
        }

        var jailLocal = Path.Combine(Root, "jail.local");
        if (File.Exists(jailLocal)) list.Add(jailLocal);

        if (Directory.Exists(jailD))
        {
            list.AddRange(Directory.GetFiles(jailD, "*.local", SearchOption.TopDirectoryOnly).OrderBy(s => s));
        }

        return list;
    }

    private IEnumerable<(string section, string key, string value)> EmitKeyValues(string path)
    {
        string? currentSection = null;

        foreach (var rawLine in ReadAllLinesMerged(path))
        {
            var line = rawLine.Trim();
            if (IsCommentOrBlank(line)) continue;

            if (IsSection(line, out var sec))
            {
                currentSection = sec;
                continue;
            }

            if (currentSection is null) continue;
            if (!TrySplitKeyValue(line, out var key, out var value)) continue;

            yield return (currentSection, key, value);
        }
    }

    // Joins lines that end with a backslash to the next line
    private static IEnumerable<string> ReadAllLinesMerged(string path)
    {
        string? pending = null;

        foreach (var lineRaw in File.ReadLines(path))
        {
            var line = lineRaw.TrimEnd();

            if (pending is null)
            {
                pending = line;
            }
            else
            {
                // When continuing from previous line, preserve leading whitespace as it may be intentional
                pending += line.TrimStart();
            }

            if (pending.EndsWith('\\'))
            {
                pending = pending[..^1];
                continue;
            }

            yield return pending;
            pending = null;
        }

        if (!string.IsNullOrEmpty(pending))
        {
            yield return pending!;
        }
    }

    private static bool IsCommentOrBlank(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return true;
        var t = line.TrimStart();
        return t.StartsWith('#') || t.StartsWith(';');
    }

    private static bool IsSection(string line, out string sectionName)
    {
        sectionName = "";
        var trimmed = line.Trim();
        if (trimmed.StartsWith('[') && trimmed.EndsWith(']') && trimmed.Length >= 3)
        {
            var s = trimmed[1..^1].Trim();
            if (s.Length > 0)
            {
                sectionName = s;
                return true;
            }
        }
        return false;
    }

    private static bool TrySplitKeyValue(string line, out string key, out string value)
    {
        // Handle "key += value", "key+ = value", and "key = value"
        key = ""; value = "";
        var idx = line.IndexOf('=');
        if (idx <= 0) return false;

        key = line[..idx].Trim();
        value = line[(idx + 1)..].Trim();

        // Handle key+ = value (append syntax where + is before =)
        if (key.EndsWith('+'))
        {
            // Keep the + to indicate append
        }

        return key.Length > 0;
    }

    private static bool ParseBool(string s)
    {
        var t = s.Trim().ToLowerInvariant();
        return t is "1" or "true" or "yes" or "enabled";
    }

    private static IEnumerable<string> SplitLogPaths(string value)
    {
        // Log paths can be separated by newlines (in multi-line values) or be on single line
        // Fail2ban typically uses newlines for multiple paths
        // Be careful not to split on spaces within a path

        // First try splitting on newlines
        var lines = value.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            // If line contains multiple paths separated by spaces (no spaces in path), split them
            // But be conservative - only split if it looks like multiple absolute paths
            if (trimmed.Contains(' ') && !trimmed.Contains("\\ "))
            {
                var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                // Check if all parts look like paths (start with /)
                if (parts.All(p => p.StartsWith('/')))
                {
                    foreach (var part in parts)
                    {
                        yield return part.Trim();
                    }
                    continue;
                }
            }

            yield return trimmed;
        }
    }

    public static int ParseDurationToSeconds(string s)
    {
        // Accept: "600", "30s", "10m", "1h", "2d", "1w", "HH:MM:SS", "DD:HH:MM:SS"
        s = s.Trim().ToLowerInvariant();

        if (int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v))
            return Math.Max(0, v);

        // Handle suffixed values
        if (TryMatchSimple(s, @"^([0-9]+)\s*s$", out var sMatch))
            return int.Parse(sMatch[1].Value, CultureInfo.InvariantCulture);
        if (TryMatchSimple(s, @"^([0-9]+)\s*m$", out var mMatch))
            return int.Parse(mMatch[1].Value, CultureInfo.InvariantCulture) * 60;
        if (TryMatchSimple(s, @"^([0-9]+)\s*h$", out var hMatch))
            return int.Parse(hMatch[1].Value, CultureInfo.InvariantCulture) * 3600;
        if (TryMatchSimple(s, @"^([0-9]+)\s*d$", out var dMatch))
            return int.Parse(dMatch[1].Value, CultureInfo.InvariantCulture) * 86400;
        if (TryMatchSimple(s, @"^([0-9]+)\s*w$", out var wMatch))
            return int.Parse(wMatch[1].Value, CultureInfo.InvariantCulture) * 604800;

        // Handle HH:MM:SS format
        if (TryMatchSimple(s, @"^([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})$", out var hmsMatch))
        {
            var hours = int.Parse(hmsMatch[1].Value, CultureInfo.InvariantCulture);
            var mins = int.Parse(hmsMatch[2].Value, CultureInfo.InvariantCulture);
            var secs = int.Parse(hmsMatch[3].Value, CultureInfo.InvariantCulture);
            return Math.Max(0, (hours * 3600) + (mins * 60) + secs);
        }

        // Handle DD:HH:MM:SS format (IPBan format)
        if (TryMatchSimple(s, @"^([0-9]+):([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})$", out var dhmsMatch))
        {
            var days = int.Parse(dhmsMatch[1].Value, CultureInfo.InvariantCulture);
            var hours = int.Parse(dhmsMatch[2].Value, CultureInfo.InvariantCulture);
            var mins = int.Parse(dhmsMatch[3].Value, CultureInfo.InvariantCulture);
            var secs = int.Parse(dhmsMatch[4].Value, CultureInfo.InvariantCulture);
            return Math.Max(0, (days * 86400) + (hours * 3600) + (mins * 60) + secs);
        }

        return 0;
    }

    private static bool TryMatchSimple(string input, string pattern, out GroupCollection groups)
    {
        var m = Regex.Match(input, pattern, RegexOptions.CultureInvariant);
        if (m.Success) { groups = m.Groups; return true; }
        groups = Match.Empty.Groups;
        return false;
    }
}

#endregion

#region Hook scaffolder (bash)

internal sealed class HookScaffolder
{
    private readonly string dir;

    public HookScaffolder(string hookDir)
    {
        dir = Path.GetFullPath(string.IsNullOrWhiteSpace(hookDir) ? Directory.GetCurrentDirectory() : hookDir);
    }

    public void WriteAll(IList<string> sources)
    {
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(Path.Combine(dir, "action.d"));

        WriteFile(Path.Combine(dir, "ipban-ban-hook.sh"), BanWrapperContent);
        WriteFile(Path.Combine(dir, "ipban-unban-hook.sh"), UnbanWrapperContent);
        WriteFile(Path.Combine(dir, "ipban-common.sh"), CommonContent);

        WriteFile(Path.Combine(dir, "action.d", "notify-stdout.sh"), ActionNotifyStdout);
        WriteFile(Path.Combine(dir, "action.d", "block-iptables.sh"), ActionBlockIptables);
        WriteFile(Path.Combine(dir, "action.d", "waf-block.sh"), ActionWafBlock);

        var mapPath = Path.Combine(dir, "actions.conf");
        if (!File.Exists(mapPath))
        {
            WriteFile(mapPath, ActionsConfDefault);
        }

        // Append commented sources for guidance
        var lines = new List<string> { "", "# --- Migrated jails (add actions as desired) ---" };
        lines.AddRange(sources.Select(s => $"# [{s}]=notify-stdout"));
        File.AppendAllLines(mapPath, lines);

        TryMarkExecutable(Path.Combine(dir, "ipban-ban-hook.sh"));
        TryMarkExecutable(Path.Combine(dir, "ipban-unban-hook.sh"));
        TryMarkExecutable(Path.Combine(dir, "ipban-common.sh"));
        TryMarkExecutable(Path.Combine(dir, "action.d", "notify-stdout.sh"));
        TryMarkExecutable(Path.Combine(dir, "action.d", "block-iptables.sh"));
        TryMarkExecutable(Path.Combine(dir, "action.d", "waf-block.sh"));
    }

    private static void WriteFile(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, content.Replace("\r\n", "\n"), new UTF8Encoding(false));
    }

    private static void TryMarkExecutable(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                // chmod +x
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "/bin/chmod",
                    Arguments = $"+x \"{path}\"",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                })?.WaitForExit(3000);
            }
        }
        catch
        {
            // best-effort
        }
    }

    // ---- Script templates ----

    private const string BanWrapperContent =
@"#!/usr/bin/env bash
set -euo pipefail
IP=""${1:-}""; SOURCE=""${2:-}""; USER=""${3:-}""; COUNT=""${4:-}""; LOGTXT=""${5:-}""
export IPBAN_EVENT=""ban""
exec ""$(dirname ""$0"")/ipban-common.sh"" ""$IP"" ""$SOURCE"" ""$USER"" ""$COUNT"" ""$LOGTXT""
";

    private const string UnbanWrapperContent =
@"#!/usr/bin/env bash
set -euo pipefail
IP=""${1:-}""; SOURCE=""${2:-}""
export IPBAN_EVENT=""unban""
exec ""$(dirname ""$0"")/ipban-common.sh"" ""$IP"" ""$SOURCE"" """" """" """"
";

    private const string CommonContent =
@"#!/usr/bin/env bash
set -euo pipefail
IP=""${1:-}""; SOURCE_RAW=""${2:-}""; USER=""${3:-}""; COUNT=""${4:-}""; LOGTXT=""${5:-}""
EVENT=""${IPBAN_EVENT:-ban}""
SOURCE=""$(printf '%s' ""$SOURCE_RAW"" | tr -c 'A-Za-z0-9_.:-' '-')""  # sanitize

BASE_DIR=""$(cd ""$(dirname ""$0"")"" && pwd)""
ACTIONS_DIR=""${BASE_DIR}/action.d""
MAP_FILE=""${BASE_DIR}/actions.conf""
LOGGER_TAG=""ipban""

log(){ logger -t ""$LOGGER_TAG"" ""[$EVENT] source=$SOURCE ip=$IP user=$USER count=${COUNT:-} $*""; }

# load actions
shopt -s nullglob
for f in ""$ACTIONS_DIR""/*.sh; do . ""$f""; done
shopt -u nullglob

# load map
declare -A MAP
if [[ -f ""$MAP_FILE"" ]]; then
  while IFS= read -r line; do
    line=""${line%%#*}""; line=""${line%%;*}""; line=""${line//$'\r'/}""
    [[ -z ""$line"" ]] && continue
    if [[ ""$line"" =~ ^\[([A-Za-z0-9_.:-\*]+)\][[:space:]]*=[[:space:]]*(.+)$ ]]; then
      key=""${BASH_REMATCH[1]}""; val=""${BASH_REMATCH[2]}""; val=""${val// /}""
      MAP[""$key""]=""$val""
    fi
  done < ""$MAP_FILE""
fi

# resolve actions for SOURCE
resolve() {
  local s=""$1""
  if [[ -n ""${MAP[$s]:-}"" ]]; then echo ""${MAP[$s]}""; return; fi
  for k in ""${!MAP[@]}""; do
    [[ ""$k"" == *""*""* ]] || continue
    local regex=""^${k//\*/.*}$""
    if [[ ""$s"" =~ $regex ]]; then echo ""${MAP[$k]}""; return; fi
  done
  echo ""${MAP[default]:-}""
}

LIST=""$(resolve ""$SOURCE"")""
if [[ -z ""$LIST"" ]]; then
  if declare -f ""action_${EVENT}_generic"" >/dev/null 2>&1; then
    ""action_${EVENT}_generic"" ""$IP"" ""$SOURCE"" ""$USER"" ""$COUNT"" ""$LOGTXT""
    exit 0
  fi
  log ""No actions for $SOURCE; nothing to do.""
  exit 0
fi

IFS=',' read -r -a ARR <<< ""$LIST""
for a in ""${ARR[@]}""; do
  [[ -z ""$a"" ]] && continue
  case ""$EVENT"" in
    ban)
      if declare -f ""action_ban_${a}"" >/dev/null 2>&1; then
        ""action_ban_${a}"" ""$IP"" ""$SOURCE"" ""$USER"" ""$COUNT"" ""$LOGTXT""
      else
        log ""WARN missing action_ban_${a}""
      fi
      ;;
    unban)
      if declare -f ""action_unban_${a}"" >/dev/null 2>&1; then
        ""action_unban_${a}"" ""$IP"" ""$SOURCE""
      else
        log ""WARN missing action_unban_${a}""
      fi
      ;;
    *)
      log ""ERROR unknown event $EVENT""; exit 1;;
  esac
done
";

    private const string ActionNotifyStdout =
@"# action.d/notify-stdout.sh
action_ban_notify-stdout()   { echo ""[ban]   $2 $1 user=$3 count=$4""; logger -t ipban ""[ban]   $2 $1 user=$3 count=$4""; }
action_unban_notify-stdout() { echo ""[unban] $2 $1"";                logger -t ipban ""[unban] $2 $1""; }
";

    private const string ActionBlockIptables =
@"# action.d/block-iptables.sh
action_ban_block-iptables() {
  ip=""$1""
  iptables -C INPUT -s ""$ip"" -j DROP 2>/dev/null || iptables -I INPUT -s ""$ip"" -j DROP
  logger -t ipban ""[ban] iptables drop $ip""
}
action_unban_block-iptables() {
  ip=""$1""
  iptables -D INPUT -s ""$ip"" -j DROP 2>/dev/null || true
  logger -t ipban ""[unban] iptables delete $ip""
}
";

    private const string ActionWafBlock =
@"# action.d/waf-block.sh
action_ban_waf-block()   { curl -fsS -X POST ""http://waf.local/block?ip=$1&src=$2"" >/dev/null || true; }
action_unban_waf-block() { curl -fsS -X POST ""http://waf.local/unblock?ip=$1""      >/dev/null || true; }
";

    private const string ActionsConfDefault =
@"# Map IPBan <LogFile Source=""...""> to action lists.
# Examples:
# [default]=notify-stdout
# [sshd]=block-iptables,notify-stdout
# [postfix]=block-iptables,notify-stdout
# [nginx-*]=waf-block,notify-stdout

[default]=notify-stdout
";
}

#endregion
