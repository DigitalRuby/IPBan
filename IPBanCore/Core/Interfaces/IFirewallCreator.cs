using System;
using System.Collections.Generic;
using System.Text;

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
        /// <param name="config">Config</param>
        /// <param name="previousFirewall">Previous firewall, null if none</param>
        /// <returns>Newly created firewall</returns>
        /// <exception cref="ArgumentException">Bad config</exception>
        IIPBanFirewall CreateFirewall(IPBanConfig config, IIPBanFirewall previousFirewall);
    }

    /// <summary>
    /// Default firewall loader
    /// </summary>
    public class DefaultFirewallCreator : IFirewallCreator
    {
        /// <inheritdoc />
        public IIPBanFirewall CreateFirewall(IPBanConfig config, IIPBanFirewall previousFirewall)
        {
            return IPBanFirewallUtility.CreateFirewall(config.FirewallRulePrefix, previousFirewall);
        }
    }
}
