﻿/*
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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Base firewall class that all firewall implementations should inherit from to get common default behavior and methods.
    /// All firewall classes should have a constructor with a single string parameter for the rule prefix.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.All)]
    public abstract class IPBanBaseFirewall : IIPBanFirewall
    {
        /// <summary>
        /// IS firewall disposed
        /// </summary>
        protected bool Disposed { get; private set; }

        /// <summary>
        /// Allow rule prefix
        /// </summary>
        protected string AllowRulePrefix { get; private set; }

        /// <summary>
        /// Block rule prefix
        /// </summary>
        protected string BlockRulePrefix { get; private set; }

        /// <summary>
        /// Packet event handler
        /// </summary>
        public event PacketEventDelegate PacketEvent;

        /// <inheritdoc />
        protected virtual void OnDispose()
        {
        }

        /// <inheritdoc />
        public void SendPacketEvents(IReadOnlyCollection<PacketEvent> events)
        {
            if (events.Count != 0 && PacketEvent is not null)
            {
                var eventsCopy = events.ToArray();
                Logger.Debug("Sending {0} packet events", eventsCopy.Length);
                try
                {
                    PacketEvent?.Invoke(eventsCopy);
                }
                catch (Exception ex)
                {
                    Logger.Error("Failed to send packet events", ex);
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rulePrefix">Rule prefix or null for default</param>
        public IPBanBaseFirewall(string rulePrefix)
        {
            if (!string.IsNullOrWhiteSpace(rulePrefix))
            {
                RulePrefix = rulePrefix.Trim();
            }
            AllowRulePrefix = RulePrefix + "Allow_";
            BlockRulePrefix = RulePrefix + "Block_";
        }

        /// <summary>
        /// Hide parameterless constructor
        /// </summary>
        private IPBanBaseFirewall() { }

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
