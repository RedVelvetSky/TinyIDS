using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using TinyIDS.Models;

namespace TinyIDS.Utils
{
    public static class FeatureExtractor
    {
        private static Dictionary<string, FlowInfo> flowTable = new Dictionary<string, FlowInfo>();

        public static PacketRecord ExtractFeatures(RawCapture rawPacket)
        {
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ethernetPacket = packet.Extract<EthernetPacket>();
            var ipPacket = ethernetPacket?.Extract<IPPacket>();
            var tcpPacket = ipPacket?.Extract<TcpPacket>();
            var udpPacket = ipPacket?.Extract<UdpPacket>();

            var payload = rawPacket.Data;
            var payloadSize = payload.Length;
            var entropy = CalculateEntropy(payload);

            var flowKey = $"{ipPacket?.SourceAddress}:{tcpPacket?.SourcePort ?? udpPacket?.SourcePort}->{ipPacket?.DestinationAddress}:{tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort}";
            var timestamp = rawPacket.Timeval.Date;

            // Update flow information
            var flowInfo = UpdateFlowInfo(flowKey, timestamp, payloadSize);

            return new PacketRecord
            {
                Timestamp = timestamp.ToString("o"),
                SourceMac = ethernetPacket?.SourceHardwareAddress.ToString() ?? string.Empty,
                DestinationMac = ethernetPacket?.DestinationHardwareAddress.ToString() ?? string.Empty,
                Protocol = ipPacket?.Protocol.ToString() ?? string.Empty,
                SourceIp = ipPacket?.SourceAddress.ToString() ?? string.Empty,
                DestinationIp = ipPacket?.DestinationAddress.ToString() ?? string.Empty,
                SourcePort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0,
                DestinationPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0,
                Length = payloadSize,
                Ttl = ipPacket?.TimeToLive ?? 0,
                SynFlag = tcpPacket?.Synchronize ?? false,
                AckFlag = tcpPacket?.Acknowledgment ?? false,
                FinFlag = tcpPacket?.Finished ?? false,
                RstFlag = tcpPacket?.Reset ?? false,
                WindowSize = tcpPacket?.WindowSize ?? 0,
                PayloadSize = payloadSize,
                Entropy = entropy,
                PacketsPerFlow = flowInfo.PacketCount,
                InterArrivalTime = flowInfo.LastInterArrivalTime.TotalMilliseconds,
                FlowDuration = flowInfo.FlowDuration.TotalMilliseconds
            };
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0.0;

            int[] counts = new int[256];
            foreach (byte b in data)
            {
                counts[b]++;
            }

            double entropy = 0.0;
            foreach (int count in counts)
            {
                if (count == 0) continue;
                double p = (double)count / data.Length;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        private static FlowInfo UpdateFlowInfo(string flowKey, DateTime timestamp, int payloadSize)
        {
            FlowInfo flowInfo;

            if (!flowTable.ContainsKey(flowKey))
            {
                flowInfo = new FlowInfo
                {
                    FirstPacketTimestamp = timestamp,
                    LastPacketTimestamp = timestamp,
                    PacketCount = 1,
                    TotalPayloadSize = payloadSize,
                    LastInterArrivalTime = TimeSpan.Zero
                };
                flowTable[flowKey] = flowInfo;
            }
            else
            {
                flowInfo = flowTable[flowKey];
                var interArrivalTime = timestamp - flowInfo.LastPacketTimestamp;

                if (interArrivalTime > TimeSpan.Zero) // Ensure that time difference is positive
                {
                    flowInfo.LastInterArrivalTime = interArrivalTime;
                }

                flowInfo.LastPacketTimestamp = timestamp;
                flowInfo.PacketCount++;
                flowInfo.TotalPayloadSize += payloadSize;
            }

            return flowInfo;
        }
    }

    public class FlowInfo
    {
        public DateTime FirstPacketTimestamp { get; set; }
        public DateTime LastPacketTimestamp { get; set; }
        public int PacketCount { get; set; }
        public int TotalPayloadSize { get; set; }
        public TimeSpan LastInterArrivalTime { get; set; }
        public TimeSpan FlowDuration => LastPacketTimestamp - FirstPacketTimestamp;
    }
}
