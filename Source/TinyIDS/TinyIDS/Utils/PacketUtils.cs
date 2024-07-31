using PacketDotNet;
using PcapDotNet.Core;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TinyIDS.Models;

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
                AnsiConsole.MarkupLine("[bold green]The packet is an Ethernet packet.[/]");

                if (ethernetPacket.PayloadPacket is IPPacket ipPacket)
                {
                    AnsiConsole.MarkupLine("[bold yellow]The packet is an IP packet.[/]");
                    stats.Proto = ipPacket.Protocol.ToString();

                    if (ipPacket is IPv4Packet ipv4Packet)
                    {
                        AnsiConsole.MarkupLine("[bold]The packet is an IPv4 packet.[/]");
                        stats.SrcIp = ipv4Packet.SourceAddress.ToString();
                        stats.DestIp = ipv4Packet.DestinationAddress.ToString();
                    }
                    else if (ipPacket is IPv6Packet ipv6Packet)
                    {
                        AnsiConsole.MarkupLine("[bold]The packet is an IPv6 packet.[/]");
                        stats.SrcIp = ipv6Packet.SourceAddress.ToString();
                        stats.DestIp = ipv6Packet.DestinationAddress.ToString();
                    }

                    if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                    {
                        AnsiConsole.MarkupLine("[bold]The packet is a TCP packet.[/]");
                        stats.SrcPort = tcpPacket.SourcePort;
                        stats.DestPort = tcpPacket.DestinationPort;
                    }
                    else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        AnsiConsole.MarkupLine("[bold]The packet is a UDP packet.[/]");
                        stats.SrcPort = udpPacket.SourcePort;
                        stats.DestPort = udpPacket.DestinationPort;
                    }

                    // Update statistics
                    UpdateStatistics(packet, stats);
                }
                else if (ethernetPacket.PayloadPacket is ArpPacket)
                {
                    AnsiConsole.MarkupLine("[bold yellow]The packet is an ARP packet.[/]");
                }
                else
                {
                    AnsiConsole.MarkupLine("[bold yellow]The Ethernet packet's payload is not IP or ARP.[/]");
                }
            }
            else if (packet is IPPacket ipPacketDirect)
            {
                AnsiConsole.MarkupLine("[bold]The packet is an IP packet.[/]");
                stats.Proto = ipPacketDirect.Protocol.ToString();

                if (ipPacketDirect is IPv4Packet ipv4Packet)
                {
                    AnsiConsole.MarkupLine("[bold]The packet is an IPv4 packet.[/]");
                    stats.SrcIp = ipv4Packet.SourceAddress.ToString();
                    stats.DestIp = ipv4Packet.DestinationAddress.ToString();
                }
                else if (ipPacketDirect is IPv6Packet ipv6Packet)
                {
                    AnsiConsole.MarkupLine("[bold]The packet is an IPv6 packet.[/]");
                    stats.SrcIp = ipv6Packet.SourceAddress.ToString();
                    stats.DestIp = ipv6Packet.DestinationAddress.ToString();
                }

                if (ipPacketDirect.PayloadPacket is TcpPacket tcpPacket)
                {
                    AnsiConsole.MarkupLine("[bold]The packet is a TCP packet.[/]");
                    stats.SrcPort = tcpPacket.SourcePort;
                    stats.DestPort = tcpPacket.DestinationPort;
                }
                else if (ipPacketDirect.PayloadPacket is UdpPacket udpPacket)
                {
                    AnsiConsole.MarkupLine("[bold]The packet is a UDP packet.[/]");
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

            AnsiConsole.Write(new Rule("[bold grey]END OF PACKET[/]").RuleStyle("grey").Centered());
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
            var table = new Table();
            table.AddColumn("[bold]Statistic[/]");
            table.AddColumn("[bold]Value[/]");

            table.AddRow("AvgIpt", stats.AvgIpt.ToString());
            table.AddRow("BytesIn", stats.BytesIn.ToString());
            table.AddRow("BytesOut", stats.BytesOut.ToString());
            table.AddRow("DestIp", stats.DestIp);
            table.AddRow("DestPort", stats.DestPort.ToString());
            table.AddRow("Entropy", stats.Entropy.ToString());
            table.AddRow("NumPktsIn", stats.NumPktsIn.ToString());
            table.AddRow("NumPktsOut", stats.NumPktsOut.ToString());
            table.AddRow("Proto", stats.Proto);
            table.AddRow("SrcIp", stats.SrcIp);
            table.AddRow("SrcPort", stats.SrcPort.ToString());
            table.AddRow("TimeEnd", stats.TimeEnd.ToString());
            table.AddRow("TimeStart", stats.TimeStart.ToString());
            table.AddRow("TotalEntropy", stats.TotalEntropy.ToString());
            table.AddRow("Duration", stats.Duration.ToString());

            AnsiConsole.Write(table);
        }
    }
}
