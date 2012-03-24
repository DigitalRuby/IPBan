#region Imports

using System;
using System.Collections.Generic;
using System.Configuration;
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

        public string XPath;
        public string Regex;
    }

    public class ExpressionsToBlockGroup
    {
        public string Keywords;
        public string Path;

        [XmlArray("Expressions")]
        [XmlArrayItem("Expression")]
        public ExpressionToBlock[] Expressions;
    }

    public class ExpressionsToBlock
    {
        [XmlArray("Groups")]
        [XmlArrayItem("Group")]
        public ExpressionsToBlockGroup[] Groups;
    }

    public class ExpressionsToBlockConfigSectionHandler : IConfigurationSectionHandler
    {
        private const string SectionName = "ExpressionsToBlock";

        public object Create(object parent, object configContext, XmlNode section)
        {
            string config = section.SelectSingleNode("//" + SectionName).OuterXml;

            if (!string.IsNullOrWhiteSpace(config))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(ExpressionsToBlock));
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(config));
                ms.Position = 0;
                return (ExpressionsToBlock)serializer.Deserialize(ms);
            }

            return null;
        }
    }
}
