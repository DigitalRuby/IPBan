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

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// This firewall implementation does nothing, so is great for performance testing
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rulePrefix">Rule prefix</param>
    [RequiredOperatingSystemAttribute(null, Priority = -999)] // low priority, basically any other firewall is preferred unless this one is explicitly specified in the config
    public class IPBanNullFirewall(string rulePrefix = null) : IPBanBaseFirewall(rulePrefix)
    {

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public override Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public override Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public override bool DeleteRule(string ruleName)
        {
            return false;
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return [];
        }

        /// <inheritdoc />
        public override IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return [];
        }

        /// <inheritdoc />
        public override IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            return [];
        }

        /// <inheritdoc />
        public override IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            return [];
        }

        /// <inheritdoc />
        public override bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            return false;
        }

        /// <inheritdoc />
        public override bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            ruleName = null;
            return false;
        }

        /// <inheritdoc />
        public override void Truncate()
        {
        }
    }
}
