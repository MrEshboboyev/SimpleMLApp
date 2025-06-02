using PacketDotNet;
using System.Net;

namespace SimpleMLApp;

public static class PacketConverter
{
    public static EnhancedNetworkPacketData? Convert(Packet packet)
    {
        try
        {
            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var ipPacket = packet.Extract<IPPacket>();

            if (ipPacket == null)
                return null; // faqat IP paketlarni ishlaymiz

            int sourcePort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0;
            int destinationPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;

            // Fragmented holatini aniqlash (PacketDotNet da FragmentFlags yo'q bo'lishi mumkin, shuning uchun null tekshir)
            bool isFragmented = false;
            int fragmentOffset = 0;
            if (ipPacket is IPv4Packet ipv4)
            {
                //isFragmented = ipv4.FragmentFlags.HasFlag(IPv4FragmentFlags.MoreFragments) || ipv4.FragmentOffset > 0;
                fragmentOffset = ipv4.FragmentOffset;
            }

            var data = new EnhancedNetworkPacketData
            {
                // Basic packet info
                PacketLength = packet.Bytes?.Length ?? 0,
                HeaderLength = ipPacket.HeaderLength,
                PayloadLength = ipPacket.PayloadLength,

                // Protocol info
                Protocol = ipPacket.Protocol.ToString(),
                ApplicationProtocol = "", // Qo'shimcha parsing bilan to'ldirish mumkin
                ProtocolNumber = (int)ipPacket.Protocol,

                // IP and ports
                SourceIP = ipPacket.SourceAddress?.ToString() ?? string.Empty,
                DestinationIP = ipPacket.DestinationAddress?.ToString() ?? string.Empty,
                SourcePort = sourcePort,
                DestinationPort = destinationPort,

                TTL = ipPacket.TimeToLive,
                IsFragmented = isFragmented,
                FragmentOffset = fragmentOffset,

                // TCP flags
                TcpSyn = tcpPacket != null && tcpPacket.Synchronize,
                TcpAck = tcpPacket != null && tcpPacket.Acknowledgment,
                TcpFin = tcpPacket != null && tcpPacket.Finished,
                TcpRst = tcpPacket != null && tcpPacket.Reset,
                TcpPsh = tcpPacket != null && tcpPacket.Push,
                TcpUrg = tcpPacket != null && tcpPacket.Urgent,
                TcpWindowSize = tcpPacket?.WindowSize ?? 0,
                TcpSequenceNumber = tcpPacket?.SequenceNumber ?? 0,
                TcpAcknowledgmentNumber = tcpPacket?.AcknowledgmentNumber ?? 0,

                // Timing features - hozircha 0
                TimestampSeconds = 0,
                InterPacketInterval = 0,

                // Flow features - hozircha 0
                FlowPacketCount = 0,
                FlowTotalBytes = 0,
                FlowDuration = 0,
                FlowBytesPerSecond = 0,
                FlowPacketsPerSecond = 0,

                // Statistical features - hozircha 0 yoki default
                PayloadEntropy = 0,
                UniqueCharacters = 0,
                AsciiRatio = 0,

                // Behavioral features - default
                IsNightTime = false,
                IsWeekend = false,
                HourOfDay = 0,
                DayOfWeek = 0,

                // Geolocation features
                SourceCountry = "Unknown",
                DestinationCountry = "Unknown",
                IsCrossBorder = false,

                // DNS features (dummy)
                IsDnsQuery = false,
                IsDnsResponse = false,
                DnsQuestionCount = 0,
                DnsAnswerCount = 0,
                DnsDomain = "",

                // HTTP features (dummy)
                IsHttpRequest = false,
                IsHttpResponse = false,
                HttpMethod = "",
                HttpStatusCode = 0,
                HttpUserAgent = "",
                HttpHost = "",

                // Network anomaly indicators
                IsBroadcast = packet.Bytes != null && packet.Bytes.Length > 0 && packet.Bytes[0] == 0xFF,
                IsMulticast = packet.Bytes != null && packet.Bytes.Length > 0 && packet.Bytes[0] >= 224 && packet.Bytes[0] <= 239,
                IsPrivateIP = ipPacket.SourceAddress != null && IsPrivateIp(ipPacket.SourceAddress),
                IsLoopback = ipPacket.SourceAddress != null && IPAddress.IsLoopback(ipPacket.SourceAddress),
                IsWellKnownPort = IsWellKnownPort(sourcePort),
                IsPortScanIndicator = false,

                // Label (default false, chunki bu faqat trainingda kerak)
                Label = false
            };

            return data;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        if (ip == null) return false;
        var bytes = ip.GetAddressBytes();
        return bytes.Length == 4 &&
               (bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168));
    }

    private static bool IsWellKnownPort(int port)
    {
        return port > 0 && port <= 1023;
    }
}
