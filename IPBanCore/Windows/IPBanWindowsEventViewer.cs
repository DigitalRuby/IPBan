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
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Implementation to hook into Windows event viewer
    /// </summary>
    public class IPBanWindowsEventViewer : IUpdater
    {
        private static readonly Regex invalidXmlRegex = new Regex(@"(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\uFEFF\uFFFE\uFFFF]", RegexOptions.Compiled);

        private readonly IIPBanService service;
        private EventLogQuery query;
        private EventLogWatcher watcher;
        private string previousQueryString;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="service">IPBan service interface</param>
        public IPBanWindowsEventViewer(IIPBanService service)
        {
            this.service = service;
            service.AddUpdater(this);
            Update(default);
        }

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task</returns>
        public Task Update(CancellationToken cancelToken)
        {
            SetupEventLogWatcher();
            return Task.CompletedTask;
        }

        /// <summary>
        /// Cleanup all resources
        /// </summary>
        public void Dispose()
        {
            query = null;
            if (watcher != null)
            {
                watcher.Dispose();
                watcher = null;
                service.RemoveUpdater(this);
            }
        }

        /// <summary>
        /// Process event viewer XML
        /// </summary>
        /// <param name="xml">XML</param>
        /// <returns>Log event or null if fail to parse/process</returns>
        public IPAddressLogEvent ProcessEventViewerXml(string xml)
        {
            Logger.Trace("Processing event viewer xml: {0}", xml);

            XmlDocument doc = ParseXml(xml);
            IPAddressLogEvent info = ExtractEventViewerXml(doc);
            if (info != null && info.IPAddress != null &&
                (info.Type == IPAddressEventType.FailedLogin || info.Type == IPAddressEventType.SuccessfulLogin))
            {
                if (!FindSourceAndUserNameForInfo(info, doc))
                {
                    // bad ip address
                    return null;
                }
                service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info });
                Logger.Debug("Event viewer found: {0}, {1}, {2}, {3}", info.IPAddress, info.Source, info.UserName, info.Type);
            }
            return info;
        }

        private bool FindSourceAndUserNameForInfo(IPAddressLogEvent info, XmlDocument doc)
        {
            if (string.IsNullOrWhiteSpace(info.IPAddress))
            {
                return false;
            }
            else if (string.IsNullOrWhiteSpace(info.Source))
            {
                XmlNode sourceNode = doc.SelectSingleNode("//Source");
                if (sourceNode != null)
                {
                    info.Source = sourceNode.InnerText.Trim();
                }
            }
            if (string.IsNullOrWhiteSpace(info.UserName))
            {
                XmlNode userNameNode = doc.SelectSingleNode("//Data[@Name='TargetUserName']");
                if (userNameNode is null)
                {
                    userNameNode = doc.SelectSingleNode("//TargetUserName");
                }
                if (userNameNode != null)
                {
                    info.UserName = userNameNode.InnerText.Trim();
                }
            }
            return true;
        }

        private IPAddressLogEvent ExtractEventViewerXml(XmlDocument doc)
        {
            XmlNode keywordsNode = doc.SelectSingleNode("//Keywords");
            string keywordsText = keywordsNode.InnerText;
            if (keywordsText.StartsWith("0x"))
            {
                keywordsText = keywordsText.Substring(2);
            }
            ulong keywordsULONG = ulong.Parse(keywordsText, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            IPAddressLogEvent info;
            bool foundNotifyOnly = false;
            string userName = null;
            string source = null;
            string ipAddress = null;
            DateTime? timestamp = null;
            int count = 1;
            bool mismatch;

            if (keywordsNode != null)
            {
                // we must match on keywords
                foreach (EventViewerExpressionGroup group in service.Config.WindowsEventViewerGetGroupsMatchingKeywords(keywordsULONG))
                {
                    // we must match all the expressions, if even one does not match, null everything out and move on
                    foreach (EventViewerExpression expression in group.Expressions)
                    {
                        // find all the nodes, try and get an ip from any of them, all must match
                        XmlNodeList nodes = doc.SelectNodes(expression.XPath);

                        if (nodes.Count == 0)
                        {
                            if (expression.XPathIsOptional)
                            {
                                // optional expression, continue on...
                                continue;
                            }

                            Logger.Debug("No nodes found for xpath {0}", expression.XPath);
                            userName = source = ipAddress = null;
                            timestamp = null;
                            foundNotifyOnly = false;
                            count = 1;
                            break;
                        }

                        // if there is a regex, it must match
                        if (string.IsNullOrWhiteSpace(expression.Regex))
                        {
                            // if empty regex, we are just checking for the existance of the element
                            Logger.Debug("No regex, so counting as a match");
                        }
                        else
                        {
                            // try and find an ip from any of the nodes
                            mismatch = true;

                            // at least one of the nodes must match the regex
                            foreach (XmlNode node in nodes)
                            {
                                // if we get a match, stop checking nodes
                                info = IPBanService.GetIPAddressEventsFromRegex(expression.RegexObject, node.InnerText,
                                    dns: service.DnsLookup).FirstOrDefault();
                                if (info != null)
                                {
                                    mismatch = false;
                                    if (group.NotifyOnly)
                                    {
                                        foundNotifyOnly = true;
                                    }
                                    else if (foundNotifyOnly)
                                    {
                                        throw new InvalidDataException("Conflicting expressions in event viewer, both failed and success logins matched keywords " + group.Keywords);
                                    }

                                    // assign values from the regex
                                    userName ??= info.UserName;
                                    source ??= info.Source;
                                    ipAddress ??= info.IPAddress;
                                    timestamp ??= info.Timestamp;
                                    count = Math.Max(info.Count, count);
                                }
                            }
                            if (mismatch)
                            {
                                // match fail, we have to match ALL the nodes or we get null ip and do not ban
                                Logger.Debug("Regex {0} did not match any nodes with xpath {1}", expression.Regex, expression.XPath);
                                userName = source = ipAddress = null;
                                timestamp = null;
                                foundNotifyOnly = false;
                                count = 1;
                                break;
                            }
                        }
                    }

                    // we found everything we need, we are done
                    if (ipAddress != null)
                    {
                        // use default source if we didn't find a source override
                        source ??= group.Source;
                        break;
                    }
                }
            }

            // if we found an ip, return a match
            if (ipAddress != null)
            {
                IPAddressEventType type = (foundNotifyOnly ? IPAddressEventType.SuccessfulLogin : IPAddressEventType.FailedLogin);
                return new IPAddressLogEvent(ipAddress, userName, source, count, type, timestamp is null ? default : timestamp.Value);
            }

            // no matches
            return null;
        }

        private XmlDocument ParseXml(string xml)
        {
            xml = invalidXmlRegex.Replace(xml, string.Empty);
            XmlTextReader reader = new XmlTextReader(new StringReader(xml))
            {
                Namespaces = false
            };
            XmlReader outerReader = XmlReader.Create(reader, new XmlReaderSettings { CheckCharacters = false });
            XmlDocument doc = new XmlDocument();
            doc.Load(outerReader);

            return doc;
        }

        private void EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e != null && e.EventRecord != null)
                {
                    EventRecord rec = e.EventRecord;
                    string xml = null;
                    try
                    {
                        xml = rec.ToXml();
                    }
                    catch
                    {
                    }
                    if (xml != null)
                    {
                        ProcessEventViewerXml(xml);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
            }
        }

        private string GetEventLogQueryString(List<string> ignored)
        {
            if (service.Config is null)
            {
                return null;
            }

            StringBuilder queryString = new StringBuilder("<QueryList>");
            int id = 0;
            HashSet<string> logNames = new HashSet<string>(System.Diagnostics.Eventing.Reader.EventLogSession.GlobalSession.GetLogNames());
            foreach (EventViewerExpressionGroup group in service.Config.WindowsEventViewerExpressionsToBlock.Groups)
            {
                if (!logNames.Contains(group.Path) ||
                    (Environment.OSVersion.Version.Major < group.MinimumWindowsMajorVersion ||
                    (Environment.OSVersion.Version.Major == group.MinimumWindowsMajorVersion && Environment.OSVersion.Version.Minor < group.MinimumWindowsMinorVersion)))
                {
                    ignored?.Add(group.Path);
                }
                else
                {
                    group.AppendQueryString(queryString, ++id);
                }
            }
            queryString.Append("</QueryList>");

            return queryString.Length < 32 ? null : queryString.ToString();
        }

        private void SetupEventLogWatcher()
        {
            Exception error = null;

            for (int i = 49; i >= 0; i--)
            {
                try
                {
                    List<string> ignored = new List<string>();
                    string queryString = GetEventLogQueryString(ignored);
                    if (queryString != null && queryString != previousQueryString)
                    {
                        Logger.Warn("Event viewer query string: {0}", queryString);
                        foreach (string path in ignored)
                        {
                            Logger.Warn("Ignoring event viewer path {0}", path);
                        }

                        watcher?.Dispose();
                        query = new EventLogQuery(null, PathType.LogName, queryString);
                        watcher = new EventLogWatcher(query);
                        watcher.EventRecordWritten += EventRecordWritten;
                        watcher.Enabled = true;
                        previousQueryString = queryString;
                    }
                    error = null;
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Error(error, "Failed to create event viewer watcher, retrying {0} more times...", i);
                    error = ex;
                    Thread.Sleep(10000);
                }
            }
            if (error != null)
            {
                throw error;
            }
        }
    }
}
