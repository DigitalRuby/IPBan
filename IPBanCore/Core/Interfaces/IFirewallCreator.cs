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
    /// Allow creating a firewall from config
    /// </summary>
    public interface IFirewallCreator
    {
        /// <summary>
        /// Create a firewall
        /// </summary>
        /// <param name="allTypes">All firewall types</param>
        /// <param name="config">Config</param>
        /// <param name="previousFirewall">Previous firewall, null if none</param>
        /// <returns>Newly created firewall</returns>
        /// <exception cref="ArgumentException">Bad config</exception>
        IIPBanFirewall CreateFirewall(System.Collections.Generic.IReadOnlyCollection<Type> allTypes,
            IPBanConfig config, IIPBanFirewall previousFirewall);
    }

    /// <summary>
    /// Default firewall loader
    /// </summary>
    public class DefaultFirewallCreator : IFirewallCreator
    {
        /// <inheritdoc />
        public IIPBanFirewall CreateFirewall(System.Collections.Generic.IReadOnlyCollection<Type> allTypes,
            IPBanConfig config,
            IIPBanFirewall previousFirewall)
        {
            return IPBanFirewallUtility.CreateFirewall(allTypes, config.FirewallRulePrefix, previousFirewall);
        }
    }
}
