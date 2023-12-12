﻿using System;
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
/// <remarks>
/// Constructor
/// </remarks>
/// <param name="service">Service</param>
public sealed class IPBanIPThreatUploader(IPBanService service) : IUpdater, IIPAddressEventHandler
{
    private static readonly Uri ipThreatReportApiUri = new("https://api.ipthreat.net/api/bulkreport");
    
    private readonly IPBanService service = service;
    private readonly Random random = new();
    private readonly List<IPAddressLogEvent> events = [];

    private DateTime nextRun = IPBanService.UtcNow;

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

        // do we have an api key?
        var apiKey = (service.Config.IPThreatApiKey ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
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
            var transform =
                eventsCopy.Select(e => new
                {
                    ip = e.IPAddress,
                    flags = "BruteForce",
                    system = e.Source,
                    notes = (service.AppName + " - " + (e.LogData ?? string.Empty)).Trim(' ', '-'),
                    ts = e.Timestamp.ToString("s", CultureInfo.InvariantCulture) + "Z",
                    count = e.Count
                });
            var jsonObj = new { items = transform };
            // have to use newtonsoft here
            var postJson = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj));
            await service.RequestMaker.MakeRequestAsync(ipThreatReportApiUri,
                postJson,
                new KeyValuePair<string, object>[] { new("X-API-KEY", apiKey) },
                null,
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
                !e.External &&
                !service.Config.IsWhitelisted(e.IPAddress)));
        }
    }
}
