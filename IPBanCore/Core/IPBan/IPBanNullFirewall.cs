using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// In memory firewall that persists rules to disk. This is not meant to be used directly but rather to be used inside of other firewall implementations.
    /// Use the IsIPAddressBlocked method in your firewall implementation / packet injection / etc.
    /// Also great for unit testing.
    /// This class is thread safe.
    /// </summary>
    [RequiredOperatingSystemAttribute(null, -999)] // low priority, basically any other firewall is preferred unless this one is explicitly specified in the config
    [CustomName("Null")]
    public class IPBanNullFirewall : IIPBanFirewall
    {
        public string RulePrefix { get; }

        public IPBanNullFirewall(string rulePrefix = null)
        {
            RulePrefix = (string.IsNullOrWhiteSpace(rulePrefix) ? RulePrefix : rulePrefix);
        }

        public Task Update()
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
        }

        public IEnumerable<string> EnumerateAllowedIPAddresses()
        {
            return new string[0];
        }

        public IEnumerable<string> EnumerateBannedIPAddresses()
        {
            return new string[0];
        }

        public IEnumerable<IPAddressRange> EnumerateIPAddresses(string ruleNamePrefix = null)
        {
            return new IPAddressRange[0];
        }

        public IEnumerable<string> GetRuleNames(string ruleNamePrefix = null)
        {
            return new string[0];
        }

        public bool IsIPAddressAllowed(string ipAddress)
        {
            return false;
        }

        public bool IsIPAddressBlocked(string ipAddress, out string ruleName, int port = -1)
        {
            ruleName = null;
            return false;
        }

        public bool IsIPAddressAllowed(string ipAddress, int port = -1)
        {
            throw new System.NotImplementedException();
        }

        public void Truncate()
        {
        }
    }
}
