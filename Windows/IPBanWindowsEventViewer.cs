﻿/*
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
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

namespace DigitalRuby.IPBan
{
    public class IPBanWindowsEventViewer : IUpdater
    {
        private static readonly Regex invalidXmlRegex = new Regex(@"(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\uFEFF\uFFFE\uFFFF]", RegexOptions.Compiled);

        private IIPBanService service;
        private EventLogQuery query;
        private EventLogWatcher watcher;
        private string previousQueryString;

        public IPBanWindowsEventViewer(IIPBanService service)
        {
            this.service = service;
            service.AddUpdater(this);
            Update();
        }

        public Task Update()
        {
            SetupEventLogWatcher();
            return Task.CompletedTask;
        }

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
            IPAddressLogEvent info = null;
            bool foundNotifyOnly = false;

            if (keywordsNode != null)
            {
                // we must match on keywords
                foreach (EventViewerExpressionGroup group in service.Config.WindowsEventViewerGetGroupsMatchingKeywords(keywordsULONG))
                {
                    string userName = null;
                    string source = null;
                    foreach (EventViewerExpression expression in group.Expressions)
                    {
                        // find all the nodes, try and get an ip from any of them, all must match
                        XmlNodeList nodes = doc.SelectNodes(expression.XPath);

                        if (nodes.Count == 0)
                        {
                            IPBanLog.Debug("No nodes found for xpath {0}", expression.XPath);
                            info = null;
                            break;
                        }

                        // if there is a regex, it must match
                        if (string.IsNullOrWhiteSpace(expression.Regex))
                        {
                            // count as a match, do not modify the ip address if it was already set
                            IPBanLog.Debug("No regex, so counting as a match");
                        }
                        else
                        {
                            info = null;

                            // try and find an ip from any of the nodes
                            foreach (XmlNode node in nodes)
                            {
                                // if we get a match, stop checking nodes
                                info = IPBanService.GetIPAddressInfoFromRegex(service.DnsLookup, expression.RegexObject, node.InnerText);
                                if (info.FoundMatch)
                                {
                                    if (group.NotifyOnly)
                                    {
                                        foundNotifyOnly = true;
                                    }
                                    else if (foundNotifyOnly)
                                    {
                                        throw new InvalidDataException("Conflicting expressions in event viewer, both failed and success logins matched keywords " + group.Keywords);
                                    }
                                    userName = (userName ?? info.UserName);
                                    source = (source ?? info.Source);
                                    break;
                                }
                            }

                            if (info != null && !info.FoundMatch)
                            {
                                // match fail, null out ip, we have to match ALL the nodes or we get null ip and do not ban
                                IPBanLog.Debug("Regex {0} did not match any nodes with xpath {1}", expression.Regex, expression.XPath);
                                info = null;
                                foundNotifyOnly = false;
                                break;
                            }
                        }
                    }
                    if (info != null && info.FoundMatch && info.IPAddress != null)
                    {
                        info.UserName = (info.UserName ?? userName);
                        info.Source = info.Source ?? source ?? group.Source;
                        break;
                    }
                    info = null; // set null for next attempt
                }
            }

            if (info != null)
            {
                info.Type = (foundNotifyOnly ? IPAddressEventType.SuccessfulLogin : IPAddressEventType.FailedLogin);
            }
            return info;
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
                IPBanLog.Error(ex);
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
            try
            {
                List<string> ignored = new List<string>();
                string queryString = GetEventLogQueryString(ignored);
                if (queryString != null && queryString != previousQueryString)
                {
                    IPBanLog.Warn("Event viewer query string: {0}", queryString);
                    foreach (string path in ignored)
                    {
                        IPBanLog.Warn("Ignoring event viewer path {0}", path);
                    }

                    watcher?.Dispose();
                    query = new EventLogQuery(null, PathType.LogName, queryString);
                    watcher = new EventLogWatcher(query);
                    watcher.EventRecordWritten += EventRecordWritten;
                    watcher.Enabled = true;
                    previousQueryString = queryString;
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error("Failed to create event viewer watcher", ex);
            }
        }

        /// <summary>
        /// Process event viewer XML
        /// </summary>
        /// <param name="xml">XML</param>
        /// <returns>Log event or null if fail to parse/process</returns>
        public IPAddressLogEvent ProcessEventViewerXml(string xml)
        {
            IPBanLog.Debug("Processing event viewer xml: {0}", xml);

            XmlDocument doc = ParseXml(xml);
            IPAddressLogEvent info = ExtractEventViewerXml(doc);
            if (info != null && info.FoundMatch && (info.Type == IPAddressEventType.FailedLogin || info.Type == IPAddressEventType.SuccessfulLogin))
            {
                if (!FindSourceAndUserNameForInfo(info, doc))
                {
                    // bad ip address
                    return null;
                }
                service.AddIPAddressLogEvents(new IPAddressLogEvent[] { info });
                IPBanLog.Debug("Event viewer found: {0}, {1}, {2}, {3}", info.IPAddress, info.Source, info.UserName, info.Type);
            }
            return info;
        }
    }
}
