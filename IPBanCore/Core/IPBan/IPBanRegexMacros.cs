using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Internal class for regex macro expansion
/// </summary>
public static partial class IPBanRegexMacros
{
    private const string IP4 = @"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}";
    private const string IP6 = @"(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)";
    private const string IP4Or6 = $"(?:{IP4}|{IP6})";
    private const string DnsPart = @"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)";
    private const string FQDN = $@"(?:{DnsPart}\.)+{DnsPart}";
    private const string Host = $"(?:{IP4Or6}|{FQDN})";

    [GeneratedRegex(@"\(\?P\<([A-Za-z_]\w*)\>", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex GeneratePyNamedGroup();
    private static readonly Regex PyNamedGroup = GeneratePyNamedGroup();

    [GeneratedRegex(@"\(\?P=(?<n>[A-Za-z_]\w*)\)", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex GeneratePyNamedBackRef();
    private static readonly Regex PyNamedBackRef = GeneratePyNamedBackRef();

    [GeneratedRegex(@"\(\?(?<f>[a-zA-Z\-]+)\)", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex GenerateInlineFlags();
    private static readonly Regex InlineFlags = GenerateInlineFlags();

    /// <summary>
    /// Expand macros: &lt;HOST&gt;, &lt;IP&gt;, &lt;IPV4&gt;, &lt;IPV6&gt;, &lt;FQDN&gt;, &lt;USER&gt;, %(__prefix_line)s
    /// + normalize Python-style named groups/backrefs to .NET.
    /// </summary>
    public static string Expand(string pattern)
    {
        const string validFlags = "imnsx-"; // - means opposite

        if (string.IsNullOrWhiteSpace(pattern))
        {
            return pattern ?? string.Empty;
        }
        string s = pattern;

        s = s.Replace("%(__prefix_line)s", ".*?", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("<HOST>", $@"(?<ipaddress>{Host})", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("<IP>", $@"(?<ipaddress>{IP4Or6})", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("<IPV4>", $@"(?<ipaddress>{IP4})", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("<IPV6>", $@"(?<ipaddress>{IP6})", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("<FQDN>", $@"(?<fqdn>{FQDN})", StringComparison.OrdinalIgnoreCase);
        s = s.Replace("<USER>", @"[""']?(?<username>[^\s""']+)[""']?", StringComparison.OrdinalIgnoreCase);

        // Replace the Python-style opening '(?P<name>' with .NET '(?<name>' and leave the rest of the group intact
        s = PyNamedGroup.Replace(s, m => $"(?<{m.Groups[1].Value}>");

        // Python named backrefs -> .NET
        s = PyNamedBackRef.Replace(s, m => $@"\k<{m.Groups["n"].Value}>");

        // Inline flags, .NET only supports imnsx
        s = InlineFlags.Replace(s, m =>
        {
            // keep imsnx; drop others since .NET doesn't support them
            // docs: https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-options
            var keepChars = m.Groups["f"].Value.Where(c => validFlags.Contains(char.ToLowerInvariant(c))); 
            var keep = new string([.. keepChars]);
            return string.IsNullOrEmpty(keep) ? string.Empty : $"(?{keep})";
        });
        return s;
    }
}
