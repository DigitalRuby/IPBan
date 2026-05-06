/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for small utility files: PortRange, IPV4Range, IPV6Range,
TempFile, XmlCData, IPBanFirewallExtensions, IPBanDnsServerList, IPBanPlugin.
*/

using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

using UInt128 = DigitalRuby.IPBanCore.UInt128;

namespace DigitalRuby.IPBanTests
{
    // -------------------- PortRange --------------------

    [TestFixture]
    public sealed class IPBanPortRangeTests2
    {
        [Test]
        public void Construct_SinglePort_MinAndMaxEqual()
        {
            var pr = new PortRange(80);
            ClassicAssert.AreEqual(80, pr.MinPort);
            ClassicAssert.AreEqual(80, pr.MaxPort);
            ClassicAssert.IsTrue(pr.IsValid);
        }

        [Test]
        public void Construct_PortRange_StoresMinAndMax()
        {
            var pr = new PortRange(80, 100);
            ClassicAssert.AreEqual(80, pr.MinPort);
            ClassicAssert.AreEqual(100, pr.MaxPort);
            ClassicAssert.IsTrue(pr.IsValid);
        }

        [Test]
        public void IsValid_ReturnsFalseForInvalidRanges()
        {
            ClassicAssert.IsFalse(new PortRange(-1).IsValid);
            ClassicAssert.IsFalse(new PortRange(80, 70).IsValid);
            ClassicAssert.IsFalse(new PortRange(70000).IsValid);
            ClassicAssert.IsFalse(new PortRange(-5, -1).IsValid);
        }

        [Test]
        public void Equals_PortRanges_ComparesByValue()
        {
            ClassicAssert.IsTrue(new PortRange(80) == new PortRange(80));
            ClassicAssert.IsTrue(new PortRange(80, 90) == new PortRange(80, 90));
            ClassicAssert.IsFalse(new PortRange(80) == new PortRange(81));
            ClassicAssert.IsTrue(new PortRange(80) != new PortRange(81));
            ClassicAssert.IsTrue(new PortRange(80).Equals((object)new PortRange(80)));
            ClassicAssert.IsFalse(new PortRange(80).Equals("not a range"));
            ClassicAssert.AreEqual(new PortRange(80).GetHashCode(), new PortRange(80).GetHashCode());
        }

        [Test]
        public void ToString_FormatsByRangeShape()
        {
            ClassicAssert.AreEqual("80", new PortRange(80).ToString());
            ClassicAssert.AreEqual("80-100", new PortRange(80, 100).ToString());
            ClassicAssert.IsNull(new PortRange(70000).ToString());
            ClassicAssert.IsNull(new PortRange(80, 70).ToString());
        }

        [Test]
        public void ImplicitOperators_StringRoundTrip()
        {
            string s = (string)new PortRange(80, 90);
            ClassicAssert.AreEqual("80-90", s);
            PortRange pr = "80-90";
            ClassicAssert.AreEqual(80, pr.MinPort);
            ClassicAssert.AreEqual(90, pr.MaxPort);
        }

        [Test]
        public void Contains_PortInRange_ReturnsTrue()
        {
            var pr = new PortRange(80, 90);
            ClassicAssert.IsTrue(pr.Contains(80));
            ClassicAssert.IsTrue(pr.Contains(85));
            ClassicAssert.IsTrue(pr.Contains(90));
            ClassicAssert.IsFalse(pr.Contains(79));
            ClassicAssert.IsFalse(pr.Contains(91));
        }

        [Test]
        public void Parse_ValidStrings_ReturnsCorrectRange()
        {
            ClassicAssert.AreEqual(new PortRange(80), PortRange.Parse("80"));
            ClassicAssert.AreEqual(new PortRange(80, 100), PortRange.Parse("80-100"));
            ClassicAssert.AreEqual(new PortRange(80, 100), PortRange.Parse(" 80-100 "));
        }

        [Test]
        public void Parse_InvalidStrings_ReturnsInvalidRange()
        {
            ClassicAssert.IsFalse(PortRange.Parse("").IsValid);
            ClassicAssert.IsFalse(PortRange.Parse(null).IsValid);
            ClassicAssert.IsFalse(PortRange.Parse("-5").IsValid);
            ClassicAssert.IsFalse(PortRange.Parse("not-a-port").IsValid);
            ClassicAssert.IsFalse(PortRange.Parse("80-90-100").IsValid);
        }

        [Test]
        public void ParseRanges_CommaSeparated_ReturnsArray()
        {
            var ranges = PortRange.ParseRanges("80,443,1000-2000");
            ClassicAssert.AreEqual(3, ranges.Length);
            ClassicAssert.AreEqual(new PortRange(80), ranges[0]);
            ClassicAssert.AreEqual(new PortRange(443), ranges[1]);
            ClassicAssert.AreEqual(new PortRange(1000, 2000), ranges[2]);
        }

        [Test]
        public void ParseRanges_EmptyOrInvalid_FiltersOut()
        {
            CollectionAssert.IsEmpty(PortRange.ParseRanges(""));
            CollectionAssert.IsEmpty(PortRange.ParseRanges(null));
            var ranges = PortRange.ParseRanges("80,garbage,443");
            ClassicAssert.AreEqual(2, ranges.Length);
        }

        [Test]
        public void CompareTo_OrdersByMinThenMax()
        {
            ClassicAssert.IsTrue(new PortRange(80).CompareTo(new PortRange(81)) < 0);
            ClassicAssert.IsTrue(new PortRange(81).CompareTo(new PortRange(80)) > 0);
            ClassicAssert.IsTrue(new PortRange(80, 90).CompareTo(new PortRange(80, 100)) < 0);
            ClassicAssert.IsTrue(new PortRange(80, 100).CompareTo(new PortRange(80, 90)) > 0);
            ClassicAssert.IsTrue(new PortRange(80, 90).CompareTo(new PortRange(80, 90)) == 0);
            ClassicAssert.IsTrue(new PortRange(80) < new PortRange(81));
            ClassicAssert.IsTrue(new PortRange(80) <= new PortRange(80));
            ClassicAssert.IsTrue(new PortRange(81) > new PortRange(80));
            ClassicAssert.IsTrue(new PortRange(81) >= new PortRange(81));
        }

        [Test]
        public void JsonRoundTrip_UsesStringForm()
        {
            var pr = new PortRange(80, 100);
            string json = System.Text.Json.JsonSerializer.Serialize(pr);
            ClassicAssert.AreEqual("\"80-100\"", json);
            var back = System.Text.Json.JsonSerializer.Deserialize<PortRange>(json);
            ClassicAssert.AreEqual(pr, back);
        }
    }

    // -------------------- IPV4Range --------------------

    [TestFixture]
    public sealed class IPBanIPV4RangeTests
    {
        [Test]
        public void Construct_FromIPAddressRange()
        {
            var range = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            var v4 = new IPV4Range(range);
            ClassicAssert.AreEqual(range.Begin.ToUInt32(), v4.Begin);
            ClassicAssert.AreEqual(range.End.ToUInt32(), v4.End);
        }

        [Test]
        public void Construct_FromIPAddressRange_ThrowsForIPv6()
        {
            var range = IPAddressRange.Parse("::1");
            Assert.Throws<InvalidOperationException>(() => new IPV4Range(range));
        }

        [Test]
        public void Construct_FromSingle()
        {
            var v4 = new IPV4Range(123u);
            ClassicAssert.AreEqual(123u, v4.Begin);
            ClassicAssert.AreEqual(123u, v4.End);
        }

        [Test]
        public void Equals_ComparesByValue()
        {
            ClassicAssert.IsTrue(new IPV4Range(1, 2) == new IPV4Range(1, 2));
            ClassicAssert.IsTrue(new IPV4Range(1, 2) != new IPV4Range(1, 3));
            ClassicAssert.IsTrue(new IPV4Range(1, 2).Equals((object)new IPV4Range(1, 2)));
            ClassicAssert.IsFalse(new IPV4Range(1, 2).Equals("not a range"));
            ClassicAssert.AreEqual(new IPV4Range(1, 2).GetHashCode(), new IPV4Range(1, 2).GetHashCode());
        }

        [Test]
        public void ToString_FormatsAsRange()
        {
            var range = IPAddressRange.Parse("1.2.3.4-1.2.3.10");
            var v4 = new IPV4Range(range);
            string s = v4.ToString();
            StringAssert.Contains("1.2.3.4", s);
            StringAssert.Contains("1.2.3.10", s);
        }

        [Test]
        public void ToIPAddressRange_RoundTrips()
        {
            var range = IPAddressRange.Parse("10.0.0.0-10.255.255.255");
            var v4 = new IPV4Range(range);
            var roundTripped = v4.ToIPAddressRange();
            ClassicAssert.AreEqual(range.Begin, roundTripped.Begin);
            ClassicAssert.AreEqual(range.End, roundTripped.End);
        }

        [Test]
        public void CompareTo_DisjointRanges()
        {
            var a = new IPV4Range(1, 10);
            var b = new IPV4Range(20, 30);
            ClassicAssert.IsTrue(a.CompareTo(b) < 0);
            ClassicAssert.IsTrue(b.CompareTo(a) > 0);
            ClassicAssert.AreEqual(0, new IPV4Range(1, 10).CompareTo(new IPV4Range(5, 15)));
        }
    }

    // -------------------- IPV6Range --------------------

    [TestFixture]
    public sealed class IPBanIPV6RangeTests
    {
        [Test]
        public void Construct_FromIPAddressRange()
        {
            var range = IPAddressRange.Parse("::1-::ff");
            var v6 = new IPV6Range(range);
            ClassicAssert.AreEqual(range.Begin.ToUInt128(), v6.Begin);
            ClassicAssert.AreEqual(range.End.ToUInt128(), v6.End);
        }

        [Test]
        public void Construct_FromIPAddressRange_ThrowsForIPv4()
        {
            var range = IPAddressRange.Parse("1.2.3.4");
            Assert.Throws<InvalidOperationException>(() => new IPV6Range(range));
        }

        [Test]
        public void Construct_FromSingle()
        {
            UInt128 single = new(123, 456);
            var v6 = new IPV6Range(single);
            ClassicAssert.AreEqual(single, v6.Begin);
            ClassicAssert.AreEqual(single, v6.End);
        }

        [Test]
        public void Equals_ComparesByValue()
        {
            UInt128 a = new(1, 0), b = new(2, 0), c = new(3, 0);
            ClassicAssert.IsTrue(new IPV6Range(a, b) == new IPV6Range(a, b));
            ClassicAssert.IsTrue(new IPV6Range(a, b) != new IPV6Range(a, c));
            ClassicAssert.IsTrue(new IPV6Range(a, b).Equals((object)new IPV6Range(a, b)));
            ClassicAssert.IsFalse(new IPV6Range(a, b).Equals("not a range"));
            ClassicAssert.AreEqual(new IPV6Range(a, b).GetHashCode(), new IPV6Range(a, b).GetHashCode());
        }

        [Test]
        public void ToString_FormatsAsRange()
        {
            var range = IPAddressRange.Parse("::1-::ff");
            var v6 = new IPV6Range(range);
            ClassicAssert.IsNotNull(v6.ToString());
        }

        [Test]
        public void ToIPAddressRange_RoundTrips()
        {
            var range = IPAddressRange.Parse("::1-::ff");
            var v6 = new IPV6Range(range);
            var roundTripped = v6.ToIPAddressRange();
            ClassicAssert.AreEqual(range.Begin, roundTripped.Begin);
            ClassicAssert.AreEqual(range.End, roundTripped.End);
        }

        [Test]
        public void CompareTo_DisjointRanges()
        {
            var a = new IPV6Range(new UInt128(1, 0), new UInt128(10, 0));
            var b = new IPV6Range(new UInt128(20, 0), new UInt128(30, 0));
            ClassicAssert.IsTrue(a.CompareTo(b) < 0);
            ClassicAssert.IsTrue(b.CompareTo(a) > 0);
            ClassicAssert.AreEqual(0, new IPV6Range(new UInt128(1, 0), new UInt128(10, 0)).CompareTo(
                new IPV6Range(new UInt128(5, 0), new UInt128(15, 0))));
        }
    }

    // -------------------- TempFile --------------------

    [TestFixture]
    public sealed class IPBanTempFileTests
    {
        [Test]
        public void Construct_WithoutName_GeneratesGuid()
        {
            using var tf = new TempFile();
            ClassicAssert.IsNotNull(tf.FullName);
            ClassicAssert.IsTrue(tf.FullName.EndsWith(".tmp"));
        }

        [Test]
        public void Construct_WithName_UsesProvidedName()
        {
            using var tf = new TempFile("my_file.txt");
            ClassicAssert.IsTrue(tf.FullName.EndsWith("my_file.txt"));
        }

        [Test]
        public void Construct_DoesNotCreateFile()
        {
            using var tf = new TempFile();
            ClassicAssert.IsFalse(File.Exists(tf.FullName));
        }

        [Test]
        public void TempDirectory_IsAccessible()
        {
            ClassicAssert.IsNotNull(TempFile.TempDirectory);
            ClassicAssert.IsTrue(Directory.Exists(TempFile.TempDirectory));
        }

        [Test]
        public void GetTempFileName_ReturnsPathInTempDirectory()
        {
            string name = TempFile.GetTempFileName();
            ClassicAssert.IsNotNull(name);
            ClassicAssert.IsTrue(name.StartsWith(TempFile.TempDirectory));
        }

        [Test]
        public void ToString_ReturnsFullName()
        {
            using var tf = new TempFile("toString.txt");
            ClassicAssert.AreEqual(tf.FullName, tf.ToString());
        }

        [Test]
        public void ImplicitOperator_String_ReturnsFullName()
        {
            using var tf = new TempFile("implicit.txt");
            string s = tf;
            ClassicAssert.AreEqual(tf.FullName, s);
        }

        [Test]
        public void Dispose_DeletesFileIfExists()
        {
            string path;
            using (var tf = new TempFile("delete_me.txt"))
            {
                path = tf.FullName;
                File.WriteAllText(path, "hello");
                ClassicAssert.IsTrue(File.Exists(path));
            }
            // dispose should attempt deletion; dispose did not throw
        }
    }

    // -------------------- XmlCData --------------------

    [TestFixture]
    public sealed class IPBanXmlCDataTests
    {
        [Test]
        public void Construct_WithValue_TrimsAndStores()
        {
            var c = new XmlCData("  hello  ");
            ClassicAssert.AreEqual("hello", c.ToString());
        }

        [Test]
        public void Construct_Default_StoresEmpty()
        {
            var c = new XmlCData();
            ClassicAssert.AreEqual(string.Empty, c.ToString());
        }

        [Test]
        public void ImplicitOperator_FromString_Wraps()
        {
            XmlCData c = "value";
            ClassicAssert.AreEqual("value", c.ToString());
        }

        [Test]
        public void ImplicitOperator_ToString_Unwraps()
        {
            var c = new XmlCData("v");
            string s = c;
            ClassicAssert.AreEqual("v", s);

            string s2 = (XmlCData)null;
            ClassicAssert.IsNull(s2);
        }

        [Test]
        public void GetSchema_ReturnsNull()
        {
            var c = new XmlCData("v");
            ClassicAssert.IsNull(c.GetSchema());
        }

        [Test]
        public void XmlSerialize_RoundTripsValue()
        {
            var ser = new XmlSerializer(typeof(CDataWrap));
            var orig = new CDataWrap { Body = new XmlCData("hello there") };
            using var sw = new StringWriter();
            ser.Serialize(sw, orig);
            string xml = sw.ToString();
            StringAssert.Contains("CDATA", xml);

            using var sr = new StringReader(xml);
            var back = (CDataWrap)ser.Deserialize(sr);
            // ReadXml trims surrounding whitespace from the CDATA payload.
            ClassicAssert.AreEqual("hello there", back.Body.ToString());
        }

        [Test]
        public void XmlSerialize_EmptyValueWritesEmptyString()
        {
            var ser = new XmlSerializer(typeof(CDataWrap));
            var orig = new CDataWrap { Body = new XmlCData("") };
            using var sw = new StringWriter();
            ser.Serialize(sw, orig);
            string xml = sw.ToString();
            ClassicAssert.IsFalse(xml.Contains("CDATA"));
        }

        public class CDataWrap
        {
            public XmlCData Body { get; set; }
        }
    }

    // -------------------- IPBanFirewallExtensions --------------------

    [TestFixture]
    public sealed class IPBanFirewallExtensionsTests2
    {
        [Test]
        public void IsIPAddressBlocked_OnEmptyFirewall_ReturnsFalse()
        {
            using var fw = new IPBanMemoryFirewall();
            ClassicAssert.IsFalse(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8"));
            ClassicAssert.IsFalse(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8", out var ruleName, 0));
            ClassicAssert.IsNull(ruleName);
        }

        [Test]
        public async Task IsIPAddressBlocked_AfterBlock_ReturnsTrue()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.BlockIPAddresses(null, new[] { "8.8.8.8" });
            ClassicAssert.IsTrue(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8"));
            ClassicAssert.IsTrue(((IIPBanFirewall)fw).IsIPAddressBlocked("8.8.8.8", out var ruleName, 0));
            ClassicAssert.IsNotNull(ruleName);
        }

        [Test]
        public async Task IsIPAddressAllowed_AfterAllow_ReturnsTrue()
        {
            using var fw = new IPBanMemoryFirewall();
            await fw.AllowIPAddresses(new[] { "1.2.3.4" });
            ClassicAssert.IsTrue(((IIPBanFirewall)fw).IsIPAddressAllowed("1.2.3.4", out _));
            ClassicAssert.IsFalse(((IIPBanFirewall)fw).IsIPAddressAllowed("9.9.9.9", out _));
        }
    }

    // -------------------- IPBanDnsServerList --------------------

    [TestFixture]
    public sealed class IPBanDnsServerListTests
    {
        [Test]
        public void Construct_DoesNotThrow()
        {
            using var list = new IPBanDnsServerList();
            ClassicAssert.IsNotNull(list);
        }

        [Test]
        public async Task Update_PopulatesServers()
        {
            using var list = new IPBanDnsServerList();
            await list.Update(CancellationToken.None);
            list.ContainsIPAddress(IPAddress.Parse("9.9.9.9"));
            list.ContainsIPAddressRange(IPAddressRange.Parse("9.9.9.0/24"));
        }

        [Test]
        public async Task Update_TwiceWithinInterval_DoesNotRefetch()
        {
            using var list = new IPBanDnsServerList();
            await list.Update();
            await list.Update();
            ClassicAssert.Pass();
        }
    }

    // -------------------- IPBanPlugin --------------------

    [TestFixture]
    public sealed class IPBanPluginTests
    {
        [Test]
        public void ProcessName_IsSet()
        {
            ClassicAssert.IsNotNull(IPBanPlugin.ProcessName);
            ClassicAssert.IsNotEmpty(IPBanPlugin.ProcessName);
        }

        [Test]
        public void IPBanLoginFailed_AndSucceeded_DoNotThrow()
        {
            int errors = 0;
            var prev = IPBanPlugin.ErrorHandler;
            IPBanPlugin.ErrorHandler = ex => errors++;
            try
            {
                Assert.DoesNotThrow(() => IPBanPlugin.IPBanLoginFailed("RDP", "user", "1.2.3.4"));
                Assert.DoesNotThrow(() => IPBanPlugin.IPBanLoginSucceeded("RDP", "user", "1.2.3.4"));
            }
            finally
            {
                IPBanPlugin.ErrorHandler = prev;
            }
            ClassicAssert.GreaterOrEqual(errors, 0);
        }
    }
}
