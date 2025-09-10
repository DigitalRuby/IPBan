using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Migration helper
/// </summary>
public static class MigrationHelper
{
    /// <summary>
    /// Perform migration
    /// </summary>
    /// <param name="args">Args</param>
    /// <returns>Exit code</returns>
    public static Task<int> Migrate(string[] args)
    {
        return Task.FromResult(-1);
    }
}
