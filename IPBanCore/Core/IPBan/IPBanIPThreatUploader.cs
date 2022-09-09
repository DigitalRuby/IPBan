using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Reflection;
using System.Diagnostics.CodeAnalysis;

namespace DigitalRuby.IPBanCore;

/// <summary>
/// Sync failed logins to ipthreat api
/// </summary>
public sealed class IPBanIPThreatUploader : IUpdater, IIPAddressEventHandler
{
    private static readonly Uri ipThreatReportApiUri = new("https://api.ipthreat.net/api/bulkreport");
    
    private readonly IIPBanService service;
    private readonly Random random = new();
    private readonly List<IPAddressLogEvent> events = new();
    
    private DateTime nextRun;

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="service">Service</param>
    public IPBanIPThreatUploader(IIPBanService service)
    {
        this.service = service;
        nextRun = IPBanService.UtcNow;//.AddMinutes(random.Next(30, 91));
    }
    
    /// <inheritdoc />
    public void Dispose()
    {
        
    }

    /// <inheritdoc />
    public async Task Update(CancellationToken cancelToken = default)
    {
        // ready to run?
        var now = IPBanService.UtcNow;
        if (now < nextRun)
        {
            return;
        }

        // do we have an api key?
        var apiKey = (service.Config.IPThreatApiKey ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return;
        }
        // api key can be read from env var if starts and ends with %
        else if (apiKey.StartsWith("%") && apiKey.EndsWith("%"))
        {
            apiKey = Environment.GetEnvironmentVariable(apiKey.Trim('%'));
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                return;
            }
        }
        
        // copy events
        IReadOnlyCollection<IPAddressLogEvent> eventsCopy;
        lock (events)
        {
            eventsCopy = events.ToArray();
            events.Clear();
        }
        if (eventsCopy.Count == 0)
        {
            return;
        }

        // post json
        try
        {
            /*
            [{
                "ip": "1.2.3.4",
                "flags": "None",
                "system": "SMTP",
                "notes": "Failed password",
                "ts": "2022-09-02T15:24:07.842Z",
                "count": 1
            }]
            */
            var appName = Assembly.GetEntryAssembly()?.GetName().Name ?? string.Empty;
            appName = (appName.Contains("ipbanpro", StringComparison.OrdinalIgnoreCase) ? "ipbanpro" : "ipban");
            var version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? string.Empty;
            var transform =
                eventsCopy.Select(e => new
                {
                    ip = e.IPAddress,
                    flags = "BruteForce",
                    system = e.Source,
                    notes = $"{appName} {version}".Trim(),
                    ts = e.Timestamp.ToString("s", CultureInfo.InvariantCulture) + "Z",
                    count = 1
                });
            var jsonObj = new { items = transform };
            // have to use newtonsoft here
            var postJson = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj));
            await service.RequestMaker.MakeRequestAsync(ipThreatReportApiUri,
                postJson,
                new KeyValuePair<string, object>[] { new KeyValuePair<string, object>("X-API-KEY", apiKey) },
                cancelToken);
            Logger.Warn("Submitted {0} failed logins to ipthreat api", eventsCopy.Count);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Failed to post json to ipthreat api, please double check your IPThreatApiKey setting");
        }

        // set next run time
        nextRun = now.AddMinutes(random.Next(30, 91));
    }

    /// <inheritdoc />
    public void AddIPAddressLogEvents(IEnumerable<IPAddressLogEvent> events)
    {
        lock (events)
        {
            this.events.AddRange(events.Where(e => e.Type == IPAddressEventType.Blocked &&
                e.Count > 0 &&
                !service.Config.IsWhitelisted(e.IPAddress)));
        }
    }
}
