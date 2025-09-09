using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Internal class for regex macro expansion
/// </summary>
public static class IPBanRegexMacros
{
    /// <summary>When true, &lt;HOST&gt; includes FQDN in addition to IP.</summary>
    public const bool UseDnsHostnamesInHost = false;

    /// <summary>When true, strict IPv4/IPv6; when false, permissive (faster, noisier).</summary>
    public const bool StrictIp = true;

    // RFC 791 IPv4 and RFC 4291 IPv6 regex (without zone id)
    private const string Octet = @"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)";
    private const string IPv4 = $@"(?:{Octet}\.){{3}}{Octet}";
    private const string H16 = @"[A-Fa-f0-9]{1,4}";
    // Comprehensive IPv6 coverage (full/compressed; one '::'; optional zone id)
    private const string IPv6 =
        $@"(?:" +
          $@"(?:{H16}:){{7}}{H16}" +                         // 8 hextets
          $@"|(?:{H16}:){{1,7}}:" +                          // 1..7 + ::
          $@"|(?:{H16}:){{1,6}}:{H16}" +                     // 1..6 + :h16
          $@"|(?:{H16}:){{1,5}}(?::{H16}){{1,2}}" +          // 1..5 + :h16{1,2}
          $@"|(?:{H16}:){{1,4}}(?::{H16}){{1,3}}" +          // 1..4 + :h16{1,3}
          $@"|(?:{H16}:){{1,3}}(?::{H16}){{1,4}}" +          // 1..3 + :h16{1,4}
          $@"|(?:{H16}:){{1,2}}(?::{H16}){{1,5}}" +          // 1..2 + :h16{1,5}
          $@"|{H16}(?::{H16}){{1,6}}" +                      // 1 + :h16{1,6}
          $@"|:(?::{H16}){{1,7}}" +                          // :: + h16{1,7}
        @")" +
        $@"(?:%[0-9A-Za-z.\-]+)?";                           // zone id

    private const string IPPermissive = @"(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Fa-f0-9:]+)";
    // DNS label: single char OR start with alphanumeric, middle can have hyphens, end with alphanumeric
    private const string DnsLabel = @"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?";
    private const string FQDN = $@"(?:{DnsLabel}\.)+{DnsLabel}";

    private static string IPBoth => StrictIp ? $@"(?:{IPv4}|{IPv6})" : IPPermissive;
    private static string HostCore => UseDnsHostnamesInHost ? $@"(?:{IPBoth}|{FQDN})" : IPBoth;

    // ===== Compiled regexes for constructs that require real regex =====
    // Python -> .NET named groups/backrefs
    private static readonly Regex PyNamedGroup =
        new(@"\(\?P<([A-Za-z_]\w*)>", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex PyNamedBackref =
        new(@"\(\?P=(?<n>[A-Za-z_]\w*)\)", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    // Inline flags: keep i,m,s,x; drop others
    private static readonly Regex InlineFlags =
        new(@"\(\?(?<f>[a-zA-Z]+)\)", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Expand macros: &lt;HOST&gt;, &lt;IP&gt;, &lt;IPV4&gt;, &lt;IPV6&gt;, &lt;FQDN&gt;, &lt;USER&gt;, %(__prefix_line)s
    /// + normalize Python-style named groups/backrefs to .NET.
    /// </summary>
    public static string Expand(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return pattern ?? string.Empty;
        string s = pattern;

        // ---- Raw string (literal) replacements (fast) ----
        s = s.Replace("%(__prefix_line)s", ".*?", StringComparison.Ordinal);
        s = s.Replace("<HOST>", $@"(?<ipaddress>{HostCore})", StringComparison.Ordinal);
        s = s.Replace("<IP>", $@"(?<ipaddress>{IPBoth})", StringComparison.Ordinal);
        s = s.Replace("<IPV4>", $@"(?<ipaddress>{IPv4})", StringComparison.Ordinal);
        s = s.Replace("<IPV6>", $@"(?<ipaddress>{IPv6})", StringComparison.Ordinal);
        s = s.Replace("<FQDN>", $@"(?<fqdn>{FQDN})", StringComparison.Ordinal);
        s = s.Replace("<USER>", @"(?<username>[^\s""']+)", StringComparison.Ordinal);

        // ---- Regex-based transforms (compiled) ----
        // Python named groups -> .NET
        s = PyNamedGroup.Replace(s, m => $"(?<{m.Groups[1].Value}>)");
        // Python named backrefs -> .NET
        s = PyNamedBackref.Replace(s, m => $@"\k<{m.Groups["n"].Value}>");
        // Inline flags: keep i,m,s,x; drop others
        s = InlineFlags.Replace(s, m =>
        {
            var keep = new string([.. m.Groups["f"].Value.Where(c => "imsx".Contains(char.ToLowerInvariant(c)))]);
            return string.IsNullOrEmpty(keep) ? string.Empty : $"(?{keep})";
        });

        return s;
    }
}
