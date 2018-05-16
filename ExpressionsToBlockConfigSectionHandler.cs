#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;

#endregion Imports

namespace IPBan
{
    public class ExpressionToBlock
    {
        internal Regex RegexObject;

        public string XPath { get; set; }
        public string Regex { get; set; }
    }

    public class ExpressionsToBlockGroup
    {
        /// <summary>
        /// Keywords as a ULONG
        /// </summary>
        public ulong KeywordsULONG { get; set; }

        /// <summary>
        /// Minimum Windows major version - see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        /// </summary>
        public int MinimumWindowsMajorVersion { get; set; } = 6;

        /// <summary>
        /// Minimum Windows minor version - see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        /// </summary>
        public int MinimumWindowsMinorVersion { get; set; } = 0;

        /// <summary>
        /// Keywords backing variable, private
        /// </summary>
        private string keywords;

        /// <summary>
        /// Keywords as HEX string
        /// </summary>
        public string Keywords
        {
            get { return keywords; }
            set
            {
                keywords = value;

                // parse, removing any 0x prefix
                if (value.StartsWith("0x"))
                {
                    value = value.Substring(2);
                }                    
                KeywordsULONG = ulong.Parse(value, NumberStyles.AllowHexSpecifier);
            }
        }

        public string Path;

        [XmlArray("Expressions")]
        [XmlArrayItem("Expression")]
        public ExpressionToBlock[] Expressions { get; set; }
    }

    public class ExpressionsToBlock
    {
        [XmlArray("Groups")]
        [XmlArrayItem("Group")]
        public ExpressionsToBlockGroup[] Groups { get; set; }
    }

    public class ExpressionsToBlockConfigSectionHandler : IConfigurationSectionHandler
    {
        private const string sectionName = "ExpressionsToBlock";

        public object Create(object parent, object configContext, XmlNode section)
        {
            string config = section.SelectSingleNode("//" + sectionName).OuterXml;

            if (!string.IsNullOrWhiteSpace(config))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(ExpressionsToBlock));
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(config))
                {
                    Position = 0
                };
                ExpressionsToBlock expressions = serializer.Deserialize(ms) as ExpressionsToBlock;
                return expressions;
            }

            return null;
        }
    }
}
