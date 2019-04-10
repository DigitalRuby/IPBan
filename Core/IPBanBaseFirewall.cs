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

namespace DigitalRuby.IPBan
{
    /// <summary>
    /// Base firewall class that all firewall implementations should inherit from
    /// </summary>
    public class IPBanBaseFirewall
    {
        protected bool Disposed { get; private set; }

        protected virtual void OnDispose()
        {
        }

        /// <summary>
        /// Whether this firewall implementation is available
        /// </summary>
        /// <returns>True if available, false if not</returns>
        public static bool IsAvailable()
        {
            return true;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix or null for default</param>
        public IPBanBaseFirewall(string rulePrefix = null)
        {
            rulePrefix = rulePrefix?.Trim();
            if (!string.IsNullOrWhiteSpace(rulePrefix))
            {
                RulePrefix = rulePrefix.Trim();
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~IPBanBaseFirewall()
        {
            Dispose();
        }

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            if (!Disposed)
            {
                Disposed = true;
                OnDispose();
            }
        }

        public virtual void Update()
        {
        }

        /// <summary>
        /// Rule prefix - defaults to 'IPBan_'
        /// </summary>
        public string RulePrefix { get; } = "IPBan_";
    }
}
