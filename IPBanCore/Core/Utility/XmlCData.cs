/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://www.digitalruby.com

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


using System.Xml.Serialization;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Nasty hack for stupid xml serializer that cannot simply mark a property string as cdata
    /// </summary>
    [System.Serializable]
    public class XmlCData : IXmlSerializable
    {
        private string value;

        /// <summary>
        /// Allow direct assignment from string:
        /// CData cdata = "abc";
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static implicit operator XmlCData(string value)
        {
            return new XmlCData(value);
        }

        /// <summary>
        /// Allow direct assigment to string
        /// </summary>
        /// <param name="cdata"></param>
        /// <returns>String or null if cdata is null</returns>
        public static implicit operator string(XmlCData cdata)
        {
            return cdata?.value;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public XmlCData() : this(string.Empty)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Value</param>
        public XmlCData(string value)
        {
            this.value = (value ?? string.Empty).Trim();
        }

        /// <summary>
        /// ToString
        /// </summary>
        /// <returns>String</returns>
        public override string ToString()
        {
            return value;
        }

        /// <summary>
        /// Get xml schema
        /// </summary>
        /// <returns>Null</returns>
        public System.Xml.Schema.XmlSchema GetSchema()
        {
            return null;
        }

        /// <summary>
        /// Read xml
        /// </summary>
        /// <param name="reader">Reader</param>
        public void ReadXml(System.Xml.XmlReader reader)
        {
            value = reader.ReadElementString();
        }

        /// <summary>
        /// Write xml
        /// </summary>
        /// <param name="writer">Writer</param>
        public void WriteXml(System.Xml.XmlWriter writer)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                writer.WriteString(string.Empty);
            }
            else
            {
                writer.WriteCData("\n" + value + "\n");
            }
        }
    }
}
