//using System;
//using System.Collections.Generic;
//using System.IO;
//using PcapDotNet.Core;
//using PcapDotNet.Packets;
//using PacketDotNet; // Ensure you have the correct using directive for PacketDotNet
//using PcapDotNet.Core.Extensions;

//class Program
//{
//    static void Main(string[] args)
//    {
//        // Retrieve the device list
//        IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

//        if (allDevices.Count == 0)
//        {
//            Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
//            return;
//        }

//        // Select the first device
//        PacketDevice selectedDevice = allDevices[0];

//        // Open the device
//        using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
//        {
//            Console.WriteLine("Listening on " + selectedDevice.Description + "...");

//            // Start capturing packets
//            communicator.ReceivePackets(0, PacketHandler);
//        }
//    }

//    // Packet handler function
//    private static void PacketHandler(PacketCommunicator communicator, Packet packet)
//    {
//        // Extract packet details
//        var packetDetails = ExtractPacketDetails(packet);

//        // Write details to CSV
//        WriteToCsv(packetDetails);
//    }

//    // Function to extract packet details
//    private static Dictionary<string, string> ExtractPacketDetails(Packet packet)
//    {
//        var details = new Dictionary<string, string>();

//        // Assuming the packet is Ethernet with IPv4
//        var ipPacket = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Buffer).Extract<PacketDotNet.IpPacket>();
//        if (ipPacket == null) return details;

//        details["Timestamp"] = packet.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff");
//        details["SrcIp"] = ipPacket.SourceAddress.ToString();
//        details["DstIp"] = ipPacket.DestinationAddress.ToString();
//        details["Protocol"] = ipPacket.Protocol.ToString();
//        details["Length"] = packet.Length.ToString();

//        if (ipPacket is PacketDotNet.TcpPacket tcpPacket)
//        {
//            details["SrcPort"] = tcpPacket.SourcePort.ToString();
//            details["DstPort"] = tcpPacket.DestinationPort.ToString();
//            details["Flags"] = tcpPacket.Flags.ToString();
//            details["Checksum"] = tcpPacket.Checksum.ToString();
//        }
//        else if (ipPacket is PacketDotNet.UdpPacket udpPacket)
//        {
//            details["SrcPort"] = udpPacket.SourcePort.ToString();
//            details["DstPort"] = udpPacket.DestinationPort.ToString();
//            details["Checksum"] = udpPacket.Checksum.ToString();
//        }

//        return details;
//    }

//    // Function to write packet details to CSV
//    private static void WriteToCsv(Dictionary<string, string> packetDetails)
//    {
//        string filePath = "captured_traffic.csv";
//        bool fileExists = File.Exists(filePath);

//        using (var writer = new StreamWriter(filePath, true))
//        {
//            if (!fileExists)
//            {
//                // Write header if file does not exist
//                writer.WriteLine("Timestamp,SrcIp,DstIp,SrcPort,DstPort,Protocol,Length,Flags,Checksum");
//            }

//            writer.WriteLine(string.Join(",", packetDetails.Values));
//        }
//    }
//}
