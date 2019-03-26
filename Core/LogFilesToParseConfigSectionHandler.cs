/*
MIT License

Copyright (c) 2019 Digital Ruby, LLC - https://www.digitalruby.com

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

        [XmlElement("Regex")]
        public IPAddressLogFileScannerRegex[] Regex { get; set; }

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
                        foreach (IPAddressLogFileScannerRegex regex in file.Regex)
                        {
                            regex.Regex = regex.Regex.Trim();
                        }
                    }
                }
                return expressions;
            }

            return null;
        }
    }
}
