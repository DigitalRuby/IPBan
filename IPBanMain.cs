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
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    public static class IPBanMain
    {
        /// <summary>
        /// IPBan main method
        /// </summary>
        /// <param name="args">Args</param>
        /// <returns>Task</returns>
        public static async Task Main(string[] args)
        {
            await MainService<IPBanService>(args, () =>
            {
                // TODO: IPBan service does not use .NET hosting infrastructure, so send out the message manually, revisit this in the future using host builder
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("IPBan service started, press Ctrl+C to exit");
                }
            });
        }

        public static async Task MainService<T>(string[] args, Action started = null) where T : IPBanService
        {
            T _service = IPBanService.CreateService<T>();
            await MainService(args, async (_args) =>
            {
                // kick off start in background thread, make sure service starts up in a timely manner
                await _service.StartAsync();
                started?.Invoke();

                // wait for service to end
                await _service.WaitAsync(Timeout.Infinite);
            }, () =>
            {
                // stop the service, will cause any WaitAsync to exit
                _service.Stop();
            });
        }

        public static async Task MainService(string[] args, Func<string[], Task> start, Action stop, bool requireAdministrator = true)
        {
            try
            {
                using (IPBanServiceRunner runner = new IPBanServiceRunner(args, start, stop))
                {
                    await runner.RunAsync(requireAdministrator);
                }
            }
            catch (Exception ex)
            {
                IPBanExtensionMethods.FileWriteAllTextWithRetry(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_fail.txt"), ex.ToString());
                IPBanLog.Fatal("Fatal error starting service", ex);
            }
        }
    }
}
