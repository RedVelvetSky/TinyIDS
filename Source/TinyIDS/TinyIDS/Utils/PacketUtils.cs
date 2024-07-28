using PacketDotNet;
using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TinyIDS.Utils
{
    public static class PacketUtils
    {

        private static List<DateTime> packetTimestamps = new List<DateTime>();
        private static int totalBytes = 0;
        private static int packetCount = 0;

        private static void UpdateStatistics(Packet packet, PacketStatistics stats)
        {
            // Capture the current time
            DateTime currentTime = DateTime.Now;
            packetTimestamps.Add(currentTime);

            if (packetTimestamps.Count > 1)
            {
                double totalInterPacketTime = 0;

                for (int i = 1; i < packetTimestamps.Count; i++)
                {
                    totalInterPacketTime += (packetTimestamps[i] - packetTimestamps[i - 1]).TotalSeconds;
                }

                stats.AvgIpt = totalInterPacketTime / (packetTimestamps.Count - 1);
            }

            if (stats.TimeStart == default)
            {
                stats.TimeStart = currentTime;
            }

            stats.TimeEnd = currentTime;
            stats.NumPktsIn++;
            stats.NumPktsOut++;
            stats.BytesIn += packet.Bytes.Length;
            stats.BytesOut += packet.Bytes.Length;
            totalBytes += packet.Bytes.Length;
            packetCount++;

            // Compute entropy
            stats.Entropy = ComputeEntropy(packet.Bytes);
            stats.TotalEntropy = ComputeEntropy(packetTimestamps.SelectMany(d => BitConverter.GetBytes(d.Ticks)).ToArray());

            // Print statistics
            PrintStatistics(stats);
        }

        public static void PrintType(Packet packet)
        {
            var stats = new PacketStatistics();

            if (packet is EthernetPacket ethernetPacket)
            {
                Console.WriteLine("The packet is an Ethernet packet.");

                if (ethernetPacket.PayloadPacket is IPPacket ipPacket)
                {
                    Console.WriteLine("The packet is an IP packet.");
                    stats.Proto = ipPacket.Protocol.ToString();

                    if (ipPacket is IPv4Packet ipv4Packet)
                    {
                        Console.WriteLine("The packet is an IPv4 packet.");
                        stats.SrcIp = ipv4Packet.SourceAddress.ToString();
                        stats.DestIp = ipv4Packet.DestinationAddress.ToString();
                    }
                    else if (ipPacket is IPv6Packet ipv6Packet)
                    {
                        Console.WriteLine("The packet is an IPv6 packet.");
                        stats.SrcIp = ipv6Packet.SourceAddress.ToString();
                        stats.DestIp = ipv6Packet.DestinationAddress.ToString();
                    }

                    if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                    {
                        Console.WriteLine("The packet is a TCP packet.");
                        stats.SrcPort = tcpPacket.SourcePort;
                        stats.DestPort = tcpPacket.DestinationPort;
                    }
                    else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        Console.WriteLine("The packet is a UDP packet.");
                        stats.SrcPort = udpPacket.SourcePort;
                        stats.DestPort = udpPacket.DestinationPort;
                    }

                    // Update statistics
                    UpdateStatistics(packet, stats);
                }
                else if (ethernetPacket.PayloadPacket is ArpPacket)
                {
                    Console.WriteLine("The packet is an ARP packet.");
                }
                else
                {
                    Console.WriteLine("The Ethernet packet's payload is not IP or ARP.");
                }
            }
            else if (packet is IPPacket ipPacketDirect)
            {
                Console.WriteLine("The packet is an IP packet.");
                stats.Proto = ipPacketDirect.Protocol.ToString();

                if (ipPacketDirect is IPv4Packet ipv4Packet)
                {
                    Console.WriteLine("The packet is an IPv4 packet.");
                    stats.SrcIp = ipv4Packet.SourceAddress.ToString();
                    stats.DestIp = ipv4Packet.DestinationAddress.ToString();
                }
                else if (ipPacketDirect is IPv6Packet ipv6Packet)
                {
                    Console.WriteLine("The packet is an IPv6 packet.");
                    stats.SrcIp = ipv6Packet.SourceAddress.ToString();
                    stats.DestIp = ipv6Packet.DestinationAddress.ToString();
                }

                if (ipPacketDirect.PayloadPacket is TcpPacket tcpPacket)
                {
                    Console.WriteLine("The packet is a TCP packet.");
                    stats.SrcPort = tcpPacket.SourcePort;
                    stats.DestPort = tcpPacket.DestinationPort;
                }
                else if (ipPacketDirect.PayloadPacket is UdpPacket udpPacket)
                {
                    Console.WriteLine("The packet is a UDP packet.");
                    stats.SrcPort = udpPacket.SourcePort;
                    stats.DestPort = udpPacket.DestinationPort;
                }

                // Update statistics
                UpdateStatistics(packet, stats);
            }
            else if (packet is ArpPacket)
            {
                Console.WriteLine("The packet is an ARP packet.");
            }
            else
            {
                Console.WriteLine("Unknown packet type.");
            }
        }

        private static double ComputeEntropy(byte[] data)
        {
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

        private static void PrintStatistics(PacketStatistics stats)
        {
            Console.WriteLine($"AvgIpt: {stats.AvgIpt}");
            Console.WriteLine($"BytesIn: {stats.BytesIn}");
            Console.WriteLine($"BytesOut: {stats.BytesOut}");
            Console.WriteLine($"DestIp: {stats.DestIp}");
            Console.WriteLine($"DestPort: {stats.DestPort}");
            Console.WriteLine($"Entropy: {stats.Entropy}");
            Console.WriteLine($"NumPktsIn: {stats.NumPktsIn}");
            Console.WriteLine($"NumPktsOut: {stats.NumPktsOut}");
            Console.WriteLine($"Proto: {stats.Proto}");
            Console.WriteLine($"SrcIp: {stats.SrcIp}");
            Console.WriteLine($"SrcPort: {stats.SrcPort}");
            Console.WriteLine($"TimeEnd: {stats.TimeEnd}");
            Console.WriteLine($"TimeStart: {stats.TimeStart}");
            Console.WriteLine($"TotalEntropy: {stats.TotalEntropy}");
            Console.WriteLine($"Duration: {stats.Duration}");
        }
    }
}
