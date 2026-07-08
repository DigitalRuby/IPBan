/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com

Coverage tests for the XmlCData CDATA wrapper.
*/

using System.IO;
using System.Xml.Serialization;

using DigitalRuby.IPBanCore;

using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace DigitalRuby.IPBanTests
{
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
}
