/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Tests for the nftables JSON model and the custom enum converters that drive it.
The model is what `nft -j list ruleset` round-trips through, so any bug here
silently corrupts the firewall rules emitted by IPBanLinuxFirewallNFTables.
*/

using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
    [TestFixture]
    public sealed class IPBanNetFilterJsonTests
    {
        // -------------------- enum converters --------------------

        [Test]
        public void Family_RoundTrips_AllValues()
        {
            // Each value should serialize to its own lowercase name and read back identically.
            foreach (NetFilterFamily f in System.Enum.GetValues<NetFilterFamily>())
            {
                string json = JsonSerializer.Serialize(f);
                ClassicAssert.AreEqual($"\"{f.ToString().ToLowerInvariant()}\"", json,
                    $"family {f} should serialize as the lowercase name");

                NetFilterFamily back = JsonSerializer.Deserialize<NetFilterFamily>(json);
                ClassicAssert.AreEqual(f, back, $"round-trip failed for {f}");
            }
        }

        [Test]
        public void SetElementType_UnderscoreNamesSerializeAsHyphenated()
        {
            // Members like ipv4_addr / inet_service contain underscores. The converter writes
            // them as hyphenated lowercase tokens (ipv4-addr, inet-service).
            string ipv4 = JsonSerializer.Serialize(NetFilterSetElementType.ipv4_addr);
            string ipv6 = JsonSerializer.Serialize(NetFilterSetElementType.ipv6_addr);
            string inet = JsonSerializer.Serialize(NetFilterSetElementType.inet_service);

            ClassicAssert.AreEqual("\"ipv4-addr\"", ipv4);
            ClassicAssert.AreEqual("\"ipv6-addr\"", ipv6);
            ClassicAssert.AreEqual("\"inet-service\"", inet);
        }

        [Test]
        public void SetElementType_AcceptsBothUnderscoreAndHyphenForms()
        {
            // The read map intentionally accepts both forms — nft -j sometimes emits underscored
            // tokens (the historical schema), some other tools normalize to hyphens.
            ClassicAssert.AreEqual(NetFilterSetElementType.ipv4_addr,
                JsonSerializer.Deserialize<NetFilterSetElementType>("\"ipv4_addr\""));
            ClassicAssert.AreEqual(NetFilterSetElementType.ipv4_addr,
                JsonSerializer.Deserialize<NetFilterSetElementType>("\"ipv4-addr\""));

            ClassicAssert.AreEqual(NetFilterSetElementType.inet_service,
                JsonSerializer.Deserialize<NetFilterSetElementType>("\"inet_service\""));
            ClassicAssert.AreEqual(NetFilterSetElementType.inet_service,
                JsonSerializer.Deserialize<NetFilterSetElementType>("\"inet-service\""));
        }

        [Test]
        public void EnumConverter_InvalidTokenThrows()
        {
            // Unknown tokens must throw rather than silently default to enum value 0 — silent
            // defaulting would mask schema drift in the nft output.
            Assert.Throws<JsonException>(() =>
                JsonSerializer.Deserialize<NetFilterFamily>("\"not-a-family\""));
        }

        [Test]
        public void EnumConverter_NumericFormReadsAsCast()
        {
            // The converter accepts numeric tokens too (some tools emit numbers). Verify the
            // numeric value casts to the corresponding enum member.
            int ipNumeric = (int)NetFilterFamily.ip;
            NetFilterFamily back = JsonSerializer.Deserialize<NetFilterFamily>(ipNumeric.ToString());
            ClassicAssert.AreEqual(NetFilterFamily.ip, back);
        }

        [Test]
        public void VerdictAction_RoundTripsValuesWithoutSpecialCase()
        {
            // accept/drop/reject/queue/jump are simple words — straight round-trip.
            foreach (var action in new[]
            {
                NetFilterVerdictAction.accept,
                NetFilterVerdictAction.drop,
                NetFilterVerdictAction.reject,
                NetFilterVerdictAction.queue,
                NetFilterVerdictAction.jump,
            })
            {
                string json = JsonSerializer.Serialize(action);
                ClassicAssert.AreEqual($"\"{action}\"", json);
                ClassicAssert.AreEqual(action, JsonSerializer.Deserialize<NetFilterVerdictAction>(json));
            }
        }

        // -------------------- flags enum converter --------------------

        [Test]
        public void SetFlags_NoneSerializesAsEmptyArray()
        {
            // The Flags converter writes an empty array for the zero value.
            string json = JsonSerializer.Serialize(NetFilterSetFlags.none);
            ClassicAssert.AreEqual("[]", json);
        }

        [Test]
        public void SetFlags_NonZeroSerializesAsArrayOfTokens()
        {
            // For NetFilterSetFlags this is non-flags semantically but still goes through the
            // flags converter — verify each named value emits as a single-element array.
            ClassicAssert.AreEqual("[\"constant\"]", JsonSerializer.Serialize(NetFilterSetFlags.constant));
            ClassicAssert.AreEqual("[\"interval\"]", JsonSerializer.Serialize(NetFilterSetFlags.interval));
        }

        [Test]
        public void SetFlags_AcceptsArrayInput()
        {
            // Read array form
            NetFilterSetFlags v = JsonSerializer.Deserialize<NetFilterSetFlags>("[\"constant\"]");
            ClassicAssert.AreEqual(NetFilterSetFlags.constant, v);
        }

        [Test]
        public void SetFlags_AcceptsLegacyCommaSeparatedString()
        {
            // The converter explicitly supports comma-separated strings as a legacy input form.
            NetFilterSetFlags v = JsonSerializer.Deserialize<NetFilterSetFlags>("\"constant\"");
            ClassicAssert.AreEqual(NetFilterSetFlags.constant, v);
        }

        [Test]
        public void SetFlags_AcceptsEmptyStringAsZero()
        {
            ClassicAssert.AreEqual(NetFilterSetFlags.none,
                JsonSerializer.Deserialize<NetFilterSetFlags>("\"\""));
        }

        [Test]
        public void SetFlags_InvalidTokenThrows()
        {
            Assert.Throws<JsonException>(() =>
                JsonSerializer.Deserialize<NetFilterSetFlags>("[\"not-a-flag\"]"));
        }

        // -------------------- ruleset wrapper round-trip --------------------

        [Test]
        public void Ruleset_RoundTrip_SimpleStructure()
        {
            // Build a minimal but realistic ruleset: metainfo + table + chain + set + rule.
            // Round-trip it through JSON and verify structural equivalence.
            string json = JsonSerializer.Serialize(new NetFilterRuleset
            {
                Entries = new()
                {
                    new() { MetaInfo = new NetFilterMeta { Version = "1.0.6", JsonSchemaVersion = 1 } },
                    new() { Table = new NetFilterTable { Family = "inet", Name = "ipban" } },
                    new() { Chain = new NetFilterChain { Family = "inet", Table = "ipban", Name = "input" } },
                    new() { Set = new NetFilterSet
                    {
                        Family = "inet",
                        Table = "ipban",
                        Name = "blocked",
                        Type = "ipv4_addr",
                    } },
                }
            });

            // Sanity: JSON contains the expected high-level keys
            StringAssert.Contains("\"nftables\"", json);
            StringAssert.Contains("\"metainfo\"", json);
            StringAssert.Contains("\"table\"", json);
            StringAssert.Contains("\"chain\"", json);
            StringAssert.Contains("\"set\"", json);

            // Round-trip back into a ruleset
            var back = JsonSerializer.Deserialize<NetFilterRuleset>(json);
            ClassicAssert.IsNotNull(back);
            ClassicAssert.AreEqual(4, back.Entries.Count);
            ClassicAssert.AreEqual("1.0.6", back.Entries[0].MetaInfo.Version);
            ClassicAssert.AreEqual("ipban",  back.Entries[1].Table.Name);
            ClassicAssert.AreEqual("input",  back.Entries[2].Chain.Name);
            ClassicAssert.AreEqual("blocked", back.Entries[3].Set.Name);
        }

        [Test]
        public void Ruleset_DeserializesRealisticNftOutput()
        {
            // Snippet of the kind of JSON `nft -j list ruleset` produces for an ipban-style
            // setup. Verifies that the model accepts real nft output without throwing.
            const string nftJson = """
            {
              "nftables": [
                { "metainfo": { "version": "1.0.6", "release_name": "Lester Gooch", "json_schema_version": 1 } },
                { "table":    { "family": "inet", "name": "ipban", "handle": 1 } },
                { "chain":    { "family": "inet", "table": "ipban", "name": "input", "handle": 2, "type": "filter", "hook": "input", "prio": 0, "policy": "accept" } },
                { "set": {
                    "family": "inet",
                    "name": "ipban-blocked",
                    "table": "ipban",
                    "type": "ipv4_addr",
                    "handle": 3,
                    "flags": ["interval"],
                    "elem": ["1.2.3.4", "5.6.7.0/24"]
                  }
                }
              ]
            }
            """;

            var ruleset = JsonSerializer.Deserialize<NetFilterRuleset>(nftJson);
            ClassicAssert.IsNotNull(ruleset);
            ClassicAssert.AreEqual(4, ruleset.Entries.Count);

            var set = ruleset.Entries[3].Set;
            ClassicAssert.AreEqual("inet", set.Family);
            ClassicAssert.AreEqual("ipban-blocked", set.Name);
            ClassicAssert.AreEqual("ipv4_addr", set.Type);
            CollectionAssert.AreEqual(new[] { "interval" }, set.Flags);
            ClassicAssert.AreEqual(2, set.Elements.Count);
        }

        [Test]
        public void Ruleset_OnDeserialized_LinkingErrorsDoNotPropagate()
        {
            // The IJsonOnDeserialized hook on NetFilterRuleset wraps its linking step in a
            // try/catch so consumers can still read partial models even if rules reference
            // sets that aren't present. Pass a malformed-but-parseable shape and assert
            // deserialize doesn't throw.
            const string oddJson = """
            {
              "nftables": [
                { "rule": { "family": "inet", "table": "ipban", "chain": "input", "expr": [] } }
              ]
            }
            """;
            Assert.DoesNotThrow(() => JsonSerializer.Deserialize<NetFilterRuleset>(oddJson));
        }

        [Test]
        public void Ruleset_EmptyArrayDeserializesCleanly()
        {
            var ruleset = JsonSerializer.Deserialize<NetFilterRuleset>("{\"nftables\":[]}");
            ClassicAssert.IsNotNull(ruleset);
            ClassicAssert.AreEqual(0, ruleset.Entries.Count);
        }
    }
}
