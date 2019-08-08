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
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    public static class IPBanMain
    {
        public static async Task<int> Main(string[] args)
        {
            return await MainService<IPBanService>(args, out _);
        }

        public static Task<int> MainService<T>(string[] args) where T : IPBanService
        {
            return MainService<T>(args, out _);
        }

        public static Task<int> MainService<T>(string[] args, out T service) where T : IPBanService
        {
            T _service = IPBanService.CreateService<T>();
            service = _service;
            return MainService(args, (_args) =>
            {
                // kick off start in background thread, make sure service starts up in a timely manner
                Task.Run(() => _service.Start());
            }, () =>
            {
                _service.Stop();
            }, (_timeout) =>
            {
                return _service.Wait(_timeout);
            });
        }

        public static Task<int> MainService(string[] args, Action<string[]> start, Action stop, Func<int, bool> stopped, bool requireAdministrator = true)
        {
            try
            {
                using (IPBanServiceRunner runner = new IPBanServiceRunner(args, start, stop, stopped))
                {
                    return runner.RunAsync(requireAdministrator);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fatal error starting service: {0}", ex);
                System.IO.File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_fail.txt"), ex.ToString());
                return Task.FromResult(-1);
            }
        }
    }
}
