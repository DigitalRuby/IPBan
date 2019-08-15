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
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace DigitalRuby.IPBan
{
    public class IPBanServiceRunner : IDisposable
    {
        private IPBanWindowsServiceRunner windowsService;

        private class IPBanWindowsServiceRunner : ServiceBase
        {
            private readonly IPBanServiceRunner runner;

            protected override void OnStart(string[] args)
            {
                base.OnStart(args);
                runner.start.Invoke(args);
            }

            protected override void OnStop()
            {
                runner.Dispose();
                base.OnStop();
            }

            protected override void OnSessionChange(SessionChangeDescription changeDescription)
            {
                base.OnSessionChange(changeDescription);
            }

            protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
            {
                return base.OnPowerEvent(powerStatus);
            }

            protected virtual void Preshutdown()
            {
            }

            protected override void OnCustomCommand(int command)
            {
                // command is SERVICE_CONTROL_PRESHUTDOWN
                if (command == 0x0000000F)
                {
                    Preshutdown();
                }
                else
                {
                    base.OnCustomCommand(command);
                }
            }

            public IPBanWindowsServiceRunner(IPBanServiceRunner runner, string[] args)
            {
                runner.ThrowIfNull();
                try
                {
                    IPBanLog.Warn("Running as a Windows service");
                    this.runner = runner;
                    CanShutdown = false;
                    CanStop = CanHandleSessionChangeEvent = CanHandlePowerEvent = true;
                    var acceptedCommandsField = typeof(ServiceBase).GetField("acceptedCommands", BindingFlags.Instance | BindingFlags.NonPublic);
                    if (acceptedCommandsField != null)
                    {
                        int acceptedCommands = (int)acceptedCommandsField.GetValue(this);
                        acceptedCommands |= 0x00000100; // SERVICE_ACCEPT_PRESHUTDOWN;
                        acceptedCommandsField.SetValue(this, acceptedCommands);
                    }
                    Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);
                    System.ServiceProcess.ServiceBase[] ServicesToRun = new System.ServiceProcess.ServiceBase[] { this };
                    System.ServiceProcess.ServiceBase.Run(ServicesToRun);
                }
                catch
                {
                    // if anything fails, fallback to running as a console app
                    try
                    {
                        Dispose();
                    }
                    catch
                    {
                    }
                    IPBanLog.Warn("Failed to run as Windows service, fallback to running as console app");
                    runner.RunConsoleService(args);
                }
            }
        }

        private readonly string[] args;
        private readonly Func<string[], Task> start;
        private readonly Func<int, bool> stopped;

        private Action stop;

        private void RunWindowsService(string[] args)
        {
            if (Console.IsInputRedirected)
            {
                // create and start using Windows service APIs
                windowsService = new IPBanWindowsServiceRunner(this, args);
            }
            else
            {
                RunConsoleService(args);
            }
        }

        private void RunConsoleService(string[] args)
        {
            // setup the service
            start.Invoke(args);

            // wait for ENTER or CTRL+C to be pressed, or for the service to stop some other way
            Console.WriteLine("Press ENTER or Ctrl+C to quit");
            while ((Console.IsInputRedirected || !Console.KeyAvailable || Console.ReadKey().Key != ConsoleKey.Enter) && (stopped == null || !stopped.Invoke(500))) { }

            // stop and cleanup
            Dispose();
        }

        private void RunLinuxService(string[] args)
        {
            RunConsoleService(args);
        }

        private void AppDomainExit(object sender, EventArgs e)
        {
            Dispose();
        }

        private void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Dispose();
        }

        /// <summary>
        /// Construct and start the service
        /// </summary>
        /// <param name="args">Command line args</param>
        /// <param name="start">Start action, params are command line args. This should start the internal service.</param>
        /// <param name="stop">Stop action, this should stop the internal service.</param>
        /// <param name="stopped">Func to return bool if internal service has been stopped, can be null. Parameter is timeout. Should return true if stopped, false if not.</param>
        public IPBanServiceRunner(string[] args, Func<string[], Task> start, Action stop, Func<int, bool> stopped)
        {
            this.args = args ?? new string[0];
            start.ThrowIfNull();
            stop.ThrowIfNull();
            this.start = start;
            this.stop = stop;
            this.stopped = stopped;
            Console.CancelKeyPress += Console_CancelKeyPress;
            AppDomain.CurrentDomain.ProcessExit += AppDomainExit;
        }

        /// <summary>
        /// Run the service
        /// </summary>
        /// <param name="requireAdministrator">True to require administrator, false otherwise</param>
        /// <returns>Exit code</returns>
        public Task<int> RunAsync(bool requireAdministrator = true)
        {
            if (requireAdministrator)
            {
                IPBanExtensionMethods.RequireAdministrator();
            }

            if (args.Length != 0 && (args[0].Equals("info", StringComparison.OrdinalIgnoreCase) || args[0].Equals("-info", StringComparison.OrdinalIgnoreCase)))
            {
                IPBanLog.Warn("System info: {0}", IPBanOS.OSString());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                RunWindowsService(args);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                RunLinuxService(args);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                throw new PlatformNotSupportedException("Mac OSX is not yet supported, but may be in the future.");
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
            return Task.FromResult(0);
        }

        /// <summary>
        /// Dispose and stop
        /// </summary>
        public void Dispose()
        {
            AppDomain.CurrentDomain.ProcessExit -= AppDomainExit;
            Console.CancelKeyPress -= Console_CancelKeyPress;
            windowsService?.Stop();
            windowsService = null;
            stop?.Invoke();
            stop = null;
        }
    }
}
