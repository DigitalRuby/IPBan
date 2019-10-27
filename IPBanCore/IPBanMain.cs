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
                ExtensionMethods.FileWriteAllTextWithRetry(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_fail.txt"), ex.ToString());
                Logger.Fatal("Fatal error starting service", ex);
            }
        }
    }
}
