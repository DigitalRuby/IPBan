/*
MIT License

Copyright (c) 2012-present Digital Ruby, LLC - https://ipban.com
*/

using System;
using System.IO;
using System.Reflection;

using DigitalRuby.IPBanCore;

namespace DigitalRuby.IPBanTests
{
    internal static class IPBanServiceTestConfigHelper
    {
        private static readonly MethodInfo configSetter =
            typeof(IPBanService).GetProperty(nameof(IPBanService.Config))!.GetSetMethod(true)!;

        public static TService CreateServiceWithConfig<TService>(Func<string, string> configFileModifier = null)
            where TService : IPBanService, new()
        {
            string configPath = Path.Combine(AppContext.BaseDirectory, IPBanConfig.DefaultFileName);
            string xml = File.ReadAllText(configPath);
            if (configFileModifier is not null)
            {
                xml = configFileModifier(xml);
            }

            TService service = new()
            {
                DnsList = null,
                LocalIPAddressString = "127.0.0.1"
            };
            configSetter.Invoke(service, [IPBanConfig.LoadFromXml(xml, service.DnsLookup, service.DnsList, service.RequestMaker)]);
            return service;
        }
    }
}
