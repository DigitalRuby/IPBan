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

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Detect if we are running as part of a nUnit unit test, in order to work-around .NET core 3 bugs in unit tests (like razor).
    /// </summary>    
    public static class UnitTestDetector
    {
        /// <summary>
        /// True if running unit tests, false otherwise
        /// </summary>
        public static bool Running { get; }

        /// <summary>
        /// Static constructor
        /// </summary>
        static UnitTestDetector()
        {
            try
            {
                if ((System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name ?? string.Empty).StartsWith("testhost", StringComparison.OrdinalIgnoreCase))
                {
                    Running = true;
                    return;
                }

                foreach (System.Reflection.Assembly assem in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (assem.FullName.ToLowerInvariant().StartsWith("nunit.framework"))
                    {
                        Running = true;
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error in {nameof(UnitTestDetector)} static constructor", ex);
            }
        }
    }
}
