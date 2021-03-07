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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Block ip addresses for any ban*.txt files
    /// </summary>
    public class IPBanBlockIPAddressesUpdater : IUpdater
    {
        private readonly IIPAddressEventHandler service;
        private readonly string textFilePathDir;
        private readonly string textFilePathMask;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="service">Service</param>
        /// <param name="textFilePathMask">Path / mask to text file to ban ip addresses from</param>
        public IPBanBlockIPAddressesUpdater(IIPAddressEventHandler service, string textFilePathMask)
        {
            service.ThrowIfNull();
            this.service = service;
            this.textFilePathDir = Path.GetDirectoryName(textFilePathMask);
            this.textFilePathMask = Path.GetFileName(textFilePathMask);
        }

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Update - if the text file path exists, all ip addresses from each line will be banned
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        public async Task Update(CancellationToken cancelToken)
        {
            try
            {
                foreach (string file in Directory.GetFiles(textFilePathDir, textFilePathMask, SearchOption.TopDirectoryOnly))
                {
                    string[] lines = (await File.ReadAllLinesAsync(file, cancelToken)).Where(l => IPAddress.TryParse(l, out _)).ToArray();
                    Logger.Warn("Queueing {0} ip addresses to ban from {1} file", lines.Length, file);
                    List<IPAddressLogEvent> bans = new();
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
                    ExtensionMethods.FileDeleteWithRetry(file);
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
            }
        }
    }
}
