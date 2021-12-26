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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Base firewall class that all firewall implementations should inherit from
    /// </summary>
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public abstract class IPBanBaseFirewall : IIPBanFirewall
    {
        protected bool Disposed { get; private set; }

        protected string AllowRulePrefix { get; private set; }
        protected string BlockRulePrefix { get; private set; }
        protected string AllowRuleName { get; private set; }
        protected string BlockRuleName { get; private set; }

        /// <summary>
        /// Override in derived class to add additional rule string after the prefix
        /// </summary>
        protected virtual string RuleSuffix => string.Empty;

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
            if (!string.IsNullOrWhiteSpace(rulePrefix))
            {
                RulePrefix = rulePrefix.Trim();
            }
            RulePrefix += RuleSuffix;
            AllowRulePrefix = RulePrefix + "Allow_";
            BlockRulePrefix = RulePrefix + "Block_";
            AllowRuleName = AllowRulePrefix + "0";
            BlockRuleName = BlockRulePrefix + "0";
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
        public virtual void Dispose()
        {
            if (!Disposed)
            {
                GC.SuppressFinalize(this);
                Disposed = true;
                OnDispose();
            }
        }

        /// <summary>
        /// Update firewall, perform housekeeping, etc.
        /// </summary>
        /// <param name="cancelToken">Cancel token</param>
        /// <returns>Task</returns>
        public virtual Task Update(CancellationToken cancelToken = default)
        {
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public abstract Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<string> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <inheritdoc />
        public abstract Task<bool> BlockIPAddressesDelta(string ruleNamePrefix, IEnumerable<IPBanFirewallIPAddressDelta> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <inheritdoc />
        public abstract Task<bool> BlockIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ranges, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <inheritdoc />
        public abstract Task<bool> AllowIPAddresses(IEnumerable<string> ipAddresses, CancellationToken cancelToken = default);

        /// <inheritdoc />
        public abstract Task<bool> AllowIPAddresses(string ruleNamePrefix, IEnumerable<IPAddressRange> ipAddresses, IEnumerable<PortRange> allowedPorts = null, CancellationToken cancelToken = default);

        /// <inheritdoc />
        public abstract bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1);

        /// <inheritdoc />
        public abstract bool IsIPAddressAllowed(string ipAddress, int port = -1);

        /// <inheritdoc />
        public abstract IEnumerable<string> GetRuleNames(string ruleNamePrefix = null);

        /// <inheritdoc />
        public abstract bool DeleteRule(string ruleName);

        /// <inheritdoc />
        public abstract IEnumerable<string> EnumerateBannedIPAddresses();

        /// <inheritdoc />
        public abstract IEnumerable<string> EnumerateAllowedIPAddresses();

        /// <inheritdoc />
        public abstract IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null);

        /// <summary>
        /// Truncate
        /// </summary>
        public abstract void Truncate();

        /// <summary>
        /// Rule prefix - defaults to 'IPBan_'
        /// </summary>
        public string RulePrefix { get; } = "IPBan_";
    }
}
