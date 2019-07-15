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
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    public class IPBanBlockIPAddressesUpdater : IUpdater
    {
        private IIPAddressEventHandler service;
        private readonly string textFilePath;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="service">Service</param>
        /// <param name="textFilePath">Path to text file to unban ip addresses from or null to require manual unban call</param>
        public IPBanBlockIPAddressesUpdater(IIPAddressEventHandler service, string textFilePath)
        {
            service.ThrowIfNull();
            this.service = service;
            this.textFilePath = textFilePath;
        }

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
        }

        /// <summary>
        /// Update - if the text file path exists, all ip addresses from each line will be unbanned
        /// </summary>
        public async Task Update()
        {
            try
            {
                if (File.Exists(textFilePath))
                {
                    string[] lines = (await File.ReadAllLinesAsync(textFilePath)).Where(l => IPAddress.TryParse(l, out _)).ToArray();
                    IPBanLog.Warn("Queueing {0} ip addresses to ban from {1} file", lines.Length, textFilePath);
                    List<IPAddressLogEvent> bans = new List<IPAddressLogEvent>();
                    foreach (string[] pieces in lines.Select(l => l.Split(',')))
                    {
                        if (pieces.Length < 1)
                        {
                            continue;
                        }
                        string ipAddress = pieces[0];
                        string source = (pieces.Length < 2 ? "Block" : pieces[1]);
                        bans.Add(new IPAddressLogEvent(ipAddress, string.Empty, source, 1, IPAddressEventType.Blocked));
                    }
                    service.AddIPAddressLogEvents(bans);
                    File.Delete(textFilePath);
                }
            }
            catch (Exception ex)
            {
                IPBanLog.Error(ex);
            }
        }
    }
}
