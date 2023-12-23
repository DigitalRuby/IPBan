#nullable disable

namespace DigitalRuby.IPBanCore
{
    /// <summary>
    /// Packet event
    /// </summary>
    public sealed class PacketEvent
    {
        /// <summary>
        /// Timestamp
        /// </summary>
        [System.Text.Json.Serialization.JsonConverter(typeof(DateTimeOffsetJsonConverter))]
        public System.DateTimeOffset Timestamp { get; init; }

        /// <summary>
        /// FQDN of machine sending the event
        /// </summary>
        public string FQDN { get; init; }

        /// <summary>
        /// Source ip address of the packet
        /// </summary>
        public string LocalIpAddress { get; init; }

        /// <summary>
        /// Source port of the packet or 0 if unknown/not applicable
        /// </summary>
        public int LocalPort { get; init; }

        /// <summary>
        /// Remote ISP (if known)
        /// </summary>
        public string RemoteISP { get; set; }

        /// <summary>
        /// Remote country (if known)
        /// </summary>
        public string RemoteCountry { get; set; }

        /// <summary>
        /// Remote region (if known)
        /// </summary>
        public string RemoteRegion { get; set; }

        /// <summary>
        /// Remote city (if known)
        /// </summary>
        public string RemoteCity { get; set; }

        /// <summary>
        /// Destination ip address of the packet
        /// </summary>
        public string RemoteIpAddress { get; init; }

        /// <summary>
        /// Destination port of the packet or 0 if unknown/not applicable
        /// </summary>
        public int RemotePort { get; init; }

        /// <summary>
        /// Rule name if known, otherwise null
        /// </summary>
        public string RuleName { get; init; }

        /// <summary>
        /// RFC 1700 protocol
        /// </summary>
        public System.Net.Sockets.ProtocolType Protocol { get; init; }

        /// <summary>
        /// Whether the packet was allowed (true) or blocked (false)
        /// </summary>
        public bool Allowed { get; init; }

        /// <summary>
        /// Whether the packet is outgoing (true) or incoming (false)
        /// </summary>
        public bool Outbound { get; init; }

        /// <summary>
        /// Data
        /// </summary>
        [System.Text.Json.Serialization.JsonIgnore]

#if !NO_NEWTONSOFT_JSON
        [Newtonsoft.Json.JsonIgnore]
#endif
        [System.Runtime.Serialization.IgnoreDataMember]
        public System.IntPtr Data { get; init; }

        /// <summary>
        /// Data length
        /// </summary>
        [System.Text.Json.Serialization.JsonIgnore]
#if !NO_NEWTONSOFT_JSON
        [Newtonsoft.Json.JsonIgnore]
#endif
        [System.Runtime.Serialization.IgnoreDataMember]
        public int DataLength { get; init; }

        /// <summary>
        /// Header row to match ToString method, including newline character(s).
        /// </summary>
        public static string Header { get; } = "Timestamp|FQDN|RuleName|Protocol|Direction|LocalIpAddress|LocalPort|RemoteIpAddress|RemotePort|RemoteISP|RemoteCountry|RemoteRegion|RemoteCity" + System.Environment.NewLine;

        /// <inheritdoc />
        public override string ToString()
        {
            var dir = Outbound ? "outbound" : "inbound";
            var protocol = Protocol.ToString();
            return $"{Timestamp:s}Z|{FQDN}|{RuleName}|{protocol}|{dir}|{LocalIpAddress}|{LocalPort}|{RemoteIpAddress}|{RemotePort}|{RemoteISP}|{RemoteCountry}|{RemoteRegion}|{RemoteCity}";
        }
    }
}

#nullable restore
