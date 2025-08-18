using DigitalRuby.IPBanCore.Core.Utility;

namespace IPBanClient
{
    internal class Program
    {
        public static async Task Main(string[] args)
        {
            await CommandLineProcessor.ProcessAsync(args);
        }
    }
}
