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
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Main method helpers
    /// </summary>
    public static class IPBanMain
    {
        /// <summary>
        /// Start typed ipban service
        /// </summary>
        /// <typeparam name="T">Type of ipban service</typeparam>
        /// <param name="args">Args</param>
        /// <param name="started">Started callback</param>
        /// <returns>Task</returns>
        public static async Task MainService<T>(string[] args, Action started = null) where T : IPBanService
        {
            T service = IPBanService.CreateService<T>();
            await MainService(args, async (_args) =>
            {
                // kick off start in background thread, make sure service starts up in a timely manner
                await service.StartAsync();
                started?.Invoke();

                // wait for service to end
                await service.WaitAsync(Timeout.Infinite);
            }, () =>
            {
                // stop the service, will cause any WaitAsync to exit
                service.Stop();
            });
        }

        /// <summary>
        /// Start generic ipban service with callbacks. The service implementation should have already been created before this method is called.
        /// </summary>
        /// <param name="args">Args</param>
        /// <param name="start">Start callback, start your implementation running here</param>
        /// <param name="stop">Stop callback, stop your implementation running here</param>
        /// <param name="requireAdministrator">Whether administrator access is required</param>
        /// <returns>Task</returns>
        public static async Task MainService(string[] args, Func<string[], Task> start, Action stop, bool requireAdministrator = true)
        {
            try
            {
                using IPBanServiceRunner runner = new IPBanServiceRunner(args, start, stop);
                await runner.RunAsync(requireAdministrator);
            }
            catch (Exception ex)
            {
                ExtensionMethods.FileWriteAllTextWithRetry(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_fail.txt"), ex.ToString());
                Logger.Fatal("Fatal error starting service", ex);
            }
        }
    }
}
