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
    [RequiredOperatingSystemAttribute(null, Priority = -999)] // low priority, basically any other firewall is preferred unless this one is explicitly specified in the config
    [CustomName("Null")]
    public class IPBanNullFirewall : IIPBanFirewall
    {
        public string RulePrefix { get; }

        public IPBanNullFirewall(string rulePrefix = null)
        {
            RulePrefix = (string.IsNullOrWhiteSpace(rulePrefix) ? RulePrefix : rulePrefix);
        }

        public Task Update(CancellationToken cancelToken)
        {
            return Task.CompletedTask;
        }

        public Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        public Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts, CancellationToken cancelToken = default)
        {
            return Task.FromResult(true);
        }

        public bool DeleteRule(string ruleName)
        {
            return false;
        }

        public void Dispose()
        {
            System.GC.SuppressFinalize(this);
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return System.Array.Empty<string>();
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return System.Array.Empty<string>();
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            return System.Array.Empty<IPAddressRange>();
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            return System.Array.Empty<string>();
        }

        public bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            return false;
        }

        public bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            ruleName = null;
            return false;
        }

        public void Truncate()
        {
        }
    }
}
