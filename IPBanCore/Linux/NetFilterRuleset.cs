using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;

using DigitalRuby.IPBanCore;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Net filter family
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterFamily
{
    /// <summary>
    /// inet
    /// </summary>
    inet,

    /// <summary>
    /// ip
    /// </summary>
    ip,

    /// <summary>
    /// ip6
    /// </summary>
    ip6,

    /// <summary>
    /// arp
    /// </summary>
    arp,

    /// <summary>
    /// bridge
    /// </summary>
    bridge,

    /// <summary>
    /// netdev
    /// </summary>
    netdev
}

/// <summary>
/// Net filter set type
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterSetElementType
{
    /// <summary>
    /// ipv4_addr
    /// </summary>
    ipv4_addr,

    /// <summary>
    /// ipv6_addr
    /// </summary>
    ipv6_addr,

    /// <summary>
    /// inet_service
    /// </summary>
    inet_service,

    /// <summary>
    /// mark
    /// </summary>
    mark,

    /// <summary>
    /// ifname
    /// </summary>
    ifname
}

/// <summary>
/// Set flags
/// </summary>
[JsonConverter(typeof(JsonStringEnumFlagsLowercaseConverter))]
public enum NetFilterSetFlags
{
    /// <summary>
    /// none
    /// </summary>
    none,

    /// <summary>
    /// constant
    /// </summary>
    constant,

    /// <summary>
    /// interval
    /// </summary>
    interval
}

/// <summary>
/// Net filter verdict action
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterVerdictAction
{
    /// <summary>
    /// accept
    /// </summary>
    accept,

    /// <summary>
    /// drop
    /// </summary>
    drop,

    /// <summary>
    /// reject
    /// </summary>
    reject,

    /// <summary>
    /// queue
    /// </summary>
    queue,

    /// <summary>
    /// cont/continue
    /// </summary>
    cont,   // continue

    /// <summary>
    /// ret/return
    /// </summary>
    ret,    // return

    /// <summary>
    /// jump
    /// </summary>
    jump,

    /// <summary>
    /// goto/goto_
    /// </summary>
    goto_
}

/// <summary>
/// Expression discriminator
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterExpressionDiscriminator
{
    /// <summary>
    /// meta
    /// </summary>
    meta,

    /// <summary>
    /// payload
    /// </summary>
    payload,

    /// <summary>
    /// cmp
    /// </summary>
    cmp,

    /// <summary>
    /// lookup
    /// </summary>
    lookup,

    /// <summary>
    /// log
    /// </summary>
    log,

    /// <summary>
    /// counter
    /// </summary>
    counter,

    /// <summary>
    /// limit
    /// </summary>
    limit,

    /// <summary>
    /// verdict
    /// </summary>
    verdict,

    /// <summary>
    /// immediate
    /// </summary>
    immediate
}

/// <summary>
/// Meta key
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterMetaKey
{
    /// <summary>
    /// mark
    /// </summary>
    mark,

    /// <summary>
    /// iifname
    /// </summary>
    iifname,

    /// <summary>
    /// oifname
    /// </summary>
    oifname,

    /// <summary>
    /// nftrace
    /// </summary>
    nftrace,

    /// <summary>
    /// l4proto
    /// </summary>
    l4proto,

    /// <summary>
    /// protocol
    /// </summary>
    protocol,

    /// <summary>
    /// len
    /// </summary>
    len
}

/// <summary>
/// Payload protocol
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterPayloadProtocol
{
    /// <summary>
    /// ip
    /// </summary>
    ip,

    /// <summary>
    /// ip6
    /// </summary>
    ip6,

    /// <summary>
    /// tcp
    /// </summary>
    tcp,

    /// <summary>
    /// udp
    /// </summary>
    udp,

    /// <summary>
    /// icmp
    /// </summary>
    icmp,

    /// <summary>
    /// icmpv6
    /// </summary>
    icmpv6
}

/// <summary>
/// compare op
/// </summary>
[JsonConverter(typeof(JsonStringEnumLowercaseConverter))]
public enum NetFilterCompareOp
{
    /// <summary>
    /// eq
    /// </summary>
    eq,

    /// <summary>
    /// neq
    /// </summary>
    neq,

    /// <summary>
    /// lt
    /// </summary>
    lt,

    /// <summary>
    /// gt
    /// </summary>
    gt,

    /// <summary>
    /// lte
    /// </summary>
    lte,

    /// <summary>
    /// gte
    /// </summary>
    gte
}

/// <summary>
/// Root nftables ruleset model for round-trip JSON.
/// Keeps raw expression and element JsonElement blocks to guarantee lossless serialization.
/// </summary>
public sealed class NetFilterRuleset : IJsonOnDeserialized
{
    internal static readonly JsonSerializerOptions serializeOptions = new JsonSerializerOptions { WriteIndented = true };

    /// <summary>
    /// Entries
    /// </summary>
    [JsonPropertyName("nftables")] public List<NetFilterEntry> Entries { get; set; } = [];

    /// <inheritdoc />
    void IJsonOnDeserialized.OnDeserialized()
    {
        try
        {
            LinkSetsAndRules();
        }
        catch
        {
            // ignore linking errors – consumers can still use raw model
        }
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: serializeOptions);
    }

    /// <summary>
    /// Crawl rules and sets and establish bidirectional references based on @setName usages
    /// inside rule match expressions (right side string starting with '@').
    /// </summary>
    private void LinkSetsAndRules()
    {
        // Build dictionary of sets by name (case-insensitive)
        Dictionary<string, NetFilterSet> sets = new(StringComparer.OrdinalIgnoreCase);
        foreach (var item in Entries)
        {
            if (!string.IsNullOrWhiteSpace(item.Set?.Name) && !sets.ContainsKey(item.Set.Name))
            {
                sets[item.Set.Name] = item.Set;
            }
        }

        // Walk rules
        foreach (var item in Entries)
        {
            var rule = item.Rule;
            if (rule?.Expressions is null || rule.Expressions.Count == 0) continue;
            foreach (var expr in rule.Expressions)
            {
                if (expr.ValueKind != JsonValueKind.Object || !expr.TryGetProperty("match", out var match)) continue;
                if (!match.TryGetProperty("right", out var right)) continue;
                if (right.ValueKind == JsonValueKind.String)
                {
                    var str = right.GetString();
                    if (!string.IsNullOrWhiteSpace(str) && str.Length > 1 && str[0] == '@')
                    {
                        var setName = str[1..];
                        if (sets.TryGetValue(setName, out var set))
                        {
                            // link both ways
                            if (!rule.ReferencedSets.Contains(set))
                            {
                                rule.ReferencedSets.Add(set);
                            }
                            if (!set.ReferencingRules.Contains(rule))
                            {
                                set.ReferencingRules.Add(rule);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// <summary>
/// A single nftables item wrapper - exactly one of the properties will be non-null.
/// </summary>
public sealed class NetFilterEntry
{
    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: NetFilterRuleset.serializeOptions);
    }

    /// <summary>
    /// Meta info
    /// </summary>
    [JsonPropertyName("metainfo")] public NetFilterMeta MetaInfo { get; set; }

    /// <summary>
    /// Table
    /// </summary>
    [JsonPropertyName("table")] public NetFilterTable Table { get; set; }

    /// <summary>
    /// Chain
    /// </summary>
    [JsonPropertyName("chain")] public NetFilterChain Chain { get; set; }

    /// <summary>
    /// Set
    /// </summary>
    [JsonPropertyName("set")] public NetFilterSet Set { get; set; }

    /// <summary>
    /// Rule
    /// </summary>
    [JsonPropertyName("rule")] public NetFilterRule Rule { get; set; }
}

/// <summary>
/// Meta info
/// </summary>
public sealed class NetFilterMeta
{
    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: NetFilterRuleset.serializeOptions);
    }

    /// <summary>
    /// Version
    /// </summary>
    [JsonPropertyName("version")] public string Version { get; set; }

    /// <summary>
    /// Release name
    /// </summary>
    [JsonPropertyName("release_name")] public string ReleaseName { get; set; }

    /// <summary>
    /// Json schema version
    /// </summary>
    [JsonPropertyName("json_schema_version")] public int JsonSchemaVersion { get; set; }
}

/// <summary>
/// Table
/// </summary>
public sealed class NetFilterTable
{
    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: NetFilterRuleset.serializeOptions);
    }

    /// <summary>
    /// Family
    /// </summary>
    [JsonPropertyName("family")] public string Family { get; set; }

    /// <summary>
    /// Name
    /// </summary>
    [JsonPropertyName("name")] public string Name { get; set; }

    /// <summary>
    /// Handle
    /// </summary>
    [JsonPropertyName("handle")] public uint? Handle { get; set; }
}

/// <summary>
/// Chain
/// </summary>
public sealed class NetFilterChain
{
    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: NetFilterRuleset.serializeOptions);
    }
    
    /// <summary>
    /// Family
    /// </summary>
    [JsonPropertyName("family")] public string Family { get; set; }

    /// <summary>
    /// Table
    /// </summary>
    [JsonPropertyName("table")] public string Table { get; set; }

    /// <summary>
    /// Name
    /// </summary>
    [JsonPropertyName("name")] public string Name { get; set; }

    /// <summary>
    /// Handle
    /// </summary>
    [JsonPropertyName("handle")] public uint? Handle { get; set; }

    /// <summary>
    /// Type
    /// </summary>
    [JsonPropertyName("type")] public string Type { get; set; }

    /// <summary>
    /// Hook
    /// </summary>
    [JsonPropertyName("hook")] public string Hook { get; set; }

    /// <summary>
    /// Priority
    /// </summary>
    [JsonPropertyName("prio")] public int? Priority { get; set; }

    /// <summary>
    /// Policy
    /// </summary>
    [JsonPropertyName("policy")] public string Policy { get; set; }
}

/// <summary>
/// Nft rule preserving expression list exactly as parsed
/// </summary>
public sealed class NetFilterRule
{
    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: NetFilterRuleset.serializeOptions);
    }

    /// <summary>
    /// Family
    /// </summary>
    [JsonPropertyName("family")] public string Family { get; set; }

    /// <summary>
    /// Table
    /// </summary>
    [JsonPropertyName("table")] public string Table { get; set; }

    /// <summary>
    /// Chain
    /// </summary>
    [JsonPropertyName("chain")] public string Chain { get; set; }

    /// <summary>
    /// Handle
    /// </summary>
    [JsonPropertyName("handle")] public uint? Handle { get; set; }

    /// <summary>
    /// Comment
    /// </summary>
    [JsonPropertyName("comment")] public string Comment { get; set; }

    /// <summary>
    /// Expressions
    /// </summary>
    [JsonPropertyName("expr")] public List<JsonElement> Expressions { get; set; } = [];

    /// <summary>
    /// Referenced sets by this rule (populated after deserialization)
    /// </summary>
    [JsonIgnore] public List<NetFilterSet> ReferencedSets { get; } = [];

    /// <summary>
    /// Get/set ports
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<PortRange> Ports
    {
        /*{
            "match": {
              "op": "in",
              "left": {
                "payload": {
                  "protocol": "th",
                  "field": "dport"
                }
              },
              "right": {
                "set": [
                  {
                    "range": [
                      22,
                      25
                    ]
                  },
                  53,
                  80,
                  443,
                  {
                    "range": [
                      8000,
                      8080
                    ]
                  }
                ]
              }
            }
          },
        */
        get
        {
            var portRanges = new List<PortRange>();
            foreach (var expr in Expressions)
            {
                if (expr.ValueKind == JsonValueKind.Object &&
                    expr.TryGetProperty("match", out var match) &&
                    match.TryGetProperty("left", out var left) &&
                    left.TryGetProperty("payload", out var payload) &&
                    payload.TryGetProperty("field", out var _field) &&
                    _field.GetString() == "dport" &&
                    match.TryGetProperty("right", out var right) &&
                    right.ValueKind == JsonValueKind.Object &&
                    right.TryGetProperty("set", out var set) &&
                    set.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in set.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Number)
                        {
                            int port = item.GetInt32();
                            portRanges.Add(new PortRange(port, port));
                        }
                        else if (item.ValueKind == JsonValueKind.Object &&
                            item.TryGetProperty("range", out var rangeArray) &&
                            rangeArray.ValueKind == JsonValueKind.Array &&
                            rangeArray.GetArrayLength() == 2)
                        {
                            int start = rangeArray[0].GetInt32();
                            int end = rangeArray[1].GetInt32();
                            portRanges.Add(new PortRange(start, end));
                        }
                    }
                }
            }
            return portRanges;
        }
        set
        {
            Expressions.RemoveAll(e => e.ValueKind == JsonValueKind.Object &&
                e.TryGetProperty("match", out var match) &&
                match.TryGetProperty("left", out var left) &&
                left.TryGetProperty("payload", out var payload) &&
                payload.TryGetProperty("field", out var _field) &&
                _field.GetString() == "dport");
            if (value != null && value.Count > 0)
            {
                var ranges = IPBanFirewallUtility.MergePortRanges(value).Select(r =>
                {
                    if (r.MinPort == r.MaxPort)
                    {
                        return r.MinPort.ToString();
                    }
                    else
                    {
                        return $$"""{"range":[{{r.MinPort}},{{r.MaxPort}}]}""";
                    }
                }).ToArray();
                if (ranges is not null && ranges.Length != 0)
                {
                    var rangesString = string.Join(",", ranges);
                    string json = $$"""{"match":{"op":"in","left":{"payload":{"protocol":"tcp","field":"dport"} },"right":{"set":[{{rangesString}}]} } }""";
                    Expressions.Add(JsonDocument.Parse(json).RootElement);
                }
            }
        }
    }

    /// <summary>
    /// True for allow, false for block (drop). Setting this property will remove any existing accept/drop/reject expressions
    /// </summary>
    [JsonIgnore]
    public bool Allow
    {
        get => Expressions.Any(e => e.ValueKind == JsonValueKind.Object && e.TryGetProperty("accept", out _));
        set
        {
            Expressions.RemoveAll(e => e.ValueKind == JsonValueKind.Object && (e.TryGetProperty("accept", out _) || e.TryGetProperty("drop", out _) || e.TryGetProperty("reject", out _)));
            Expressions.Add(JsonDocument.Parse($"{{\"{(value ? "accept" : "drop")}\":null}}").RootElement);
        }
    }
}

/// <summary>
/// Nft set model retaining original element shapes (string | {range:[a,b]} | {prefix:{addr,len}})
/// </summary>
public sealed class NetFilterSet
{
    /// <inheritdoc />
    public override string ToString()
    {
        return System.Text.Json.JsonSerializer.Serialize(this, options: NetFilterRuleset.serializeOptions);
    }

    /// <summary>
    /// Family
    /// </summary>
    [JsonPropertyName("family")] public string Family { get; set; }

    /// <summary>
    /// Name
    /// </summary>
    [JsonPropertyName("name")] public string Name { get; set; }

    /// <summary>
    /// Table
    /// </summary>
    [JsonPropertyName("table")] public string Table { get; set; }

    /// <summary>
    /// Type
    /// </summary>
    [JsonPropertyName("type")] public string Type { get; set; }

    /// <summary>
    /// Handle
    /// </summary>
    [JsonPropertyName("handle")] public uint? Handle { get; set; }

    /// <summary>
    /// Comment
    /// </summary>
    [JsonPropertyName("comment")] public string Comment { get; set; }

    /// <summary>
    /// Flags
    /// </summary>
    [JsonPropertyName("flags")] public List<string> Flags { get; set; } = [];

    /// <summary>
    /// Elements
    /// </summary>
    [JsonPropertyName("elem")] public List<JsonElement> Elements { get; set; } = [];

    /// <summary>
    /// Referencing rules (populated after deserialization)
    /// </summary>
    [JsonIgnore] public List<NetFilterRule> ReferencingRules { get; } = [];

    /// <summary>
    /// Add an element by string (individual ip or ip range)
    /// </summary>
    /// <param name="value">Value</param>
    /// <returns>This set</returns>
    public NetFilterSet Add(string value)
    {
        if (IPAddressRange.TryParse(value, out var range))
        {
            return Add(range);
        }
        return this;
    }

    /// <summary>
    /// Add an element by IPAddressRange (individual ip or ip range)
    /// </summary>
    /// <param name="range">Range</param>
    /// <returns>This set</returns>
    public NetFilterSet Add(IPAddressRange range)
    {
        if (range.Single)
        {
            Elements.Add(JsonDocument.Parse($"\"{range.Begin}\"").RootElement);
        }
        else if (range.GetPrefixLength(false) > 0)
        {
            Elements.Add(JsonDocument.Parse($"{{\"prefix\":{{\"addr\":\"{range.Begin}\",\"len\":{range.GetPrefixLength(false)}}}}}").RootElement);
        }
        else
        {
            Elements.Add(JsonDocument.Parse($"{{\"range\":[\"{range.Begin}\",\"{range.End}\"]}}").RootElement);
        }

        return this;
    }

    /// <summary>
    /// Extract element entries as string (individual ips or ip ranges)
    /// </summary>
    /// <returns>Parsed elements</returns>
    public IEnumerable<string> EnumerateSetElements()
    {
        foreach (var elem in Elements)
        {
            if (elem.ValueKind == JsonValueKind.String)
            {
                yield return elem.GetString();
            }
            else if (elem.ValueKind == JsonValueKind.Object)
            {
                if (elem.TryGetProperty("range", out var rangeArray) && rangeArray.ValueKind == JsonValueKind.Array && rangeArray.GetArrayLength() == 2)
                {
                    yield return rangeArray[0].GetString() + "-" + rangeArray[1].GetString();
                }
                else if (elem.TryGetProperty("prefix", out var prefixObj) &&
                    prefixObj.TryGetProperty("addr", out var addr) &&
                    prefixObj.TryGetProperty("len", out var lenProp))
                {
                    yield return addr.GetString() + "/" + lenProp.GetInt32();
                }
            }
        }
    }
}