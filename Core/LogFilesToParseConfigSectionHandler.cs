using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace IPBan
{
    public class LogFileToParse
    {
        public string Source { get; set; }
        public string PathAndMask { get; set; }
        public bool Recursive { get; set; }
        public string Regex { get; set; }
        public string PlatformRegex { get; set; }
        public int PingInterval { get; set; } = 10000;
        public int MaxFileSize { get; set; }

        public override string ToString()
        {
            return string.Format("Path/mask: {0}, platform: {1}", PathAndMask, PlatformRegex);
        }
    }

    public class LogFilesToParse
    {
        [XmlArray("LogFiles")]
        [XmlArrayItem("LogFile")]
        public LogFileToParse[] LogFiles;
    }

    public class LogFilesToParseConfigSectionHandler : IConfigurationSectionHandler
    {
        private const string sectionName = "LogFilesToParse";

        public object Create(object parent, object configContext, XmlNode section)
        {
            string config = section.SelectSingleNode("//" + sectionName).OuterXml;

            if (!string.IsNullOrWhiteSpace(config))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(LogFilesToParse));
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(config))
                {
                    Position = 0
                };
                LogFilesToParse expressions = serializer.Deserialize(ms) as LogFilesToParse;
                if (expressions != null && expressions.LogFiles != null)
                {
                    foreach (LogFileToParse file in expressions.LogFiles)
                    {
                        file.Regex = file.Regex.Trim();
                    }
                }
                return expressions;
            }

            return null;
        }
    }
}
