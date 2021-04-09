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

using DigitalRuby.IPBanCore;

using System;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// IPBan application main method class
    /// </summary>
    public static class IPBanApp
    {
        /// <summary>
        /// IPBan main method
        /// </summary>
        /// <param name="args">Args</param>
        /// <returns>Task</returns>
        public static async Task Main(string[] args)
        {
            if (args.Length != 0 && (args[0].Equals("info", StringComparison.OrdinalIgnoreCase) ||
                args[0].Equals("-info", StringComparison.OrdinalIgnoreCase)))
            {
                Logger.Warn("System info: {0}", OSUtility.OSString());
                return;
            }

            IPBanService service = null;
            await IPBanServiceRunner.MainService(args, (CancellationToken cancelToken) =>
            {
                service = IPBanService.CreateService<IPBanService>();
                Logger.Warn("IPBan is free software created and refined over many years.");
                Logger.Warn("Please consider upgrading to the pro version for more advanced functions, shared ban lists and much more.");
                Logger.Warn("Learn more at https://ipban.com");
                return service.RunAsync(cancelToken);
            }, (CancellationToken cancelToken) =>
            {
                service?.Dispose();
                return Task.CompletedTask;
            });
        }
    }
}
