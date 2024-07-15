using System;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using SharpPcap.LibPcap;
using Spectre.Console;

namespace TinyIDS.Services
{
    public class PacketCaptureService
    {
        private ICaptureDevice _device;
        private static CaptureFileWriterDevice captureFileWriter;

        public void ListDevices()
        {
            var devices = CaptureDeviceList.Instance;

            if (devices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap or Npcap is installed.");
                return;
            }

            foreach (var device in devices)
            {
                Console.WriteLine($"{device.Name} - {device.Description}");
            }
        }

       public void StartCapture()
       {
            // Print SharpPcap version
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}, CreatingCaptureFile", ver);

            // Retrieve the device list
            var devices = LibPcapLiveDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture on: ");
            i = int.Parse(Console.ReadLine());
            Console.Write("-- Please enter the output file name: ");
            string capFile = Console.ReadLine();

            using var device = devices[i];

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, writing to {2}, hit 'Enter' to stop...",
                              device.Name, device.Description,
                              capFile);

            // open the output file
            captureFileWriter = new CaptureFileWriterDevice(capFile);
            captureFileWriter.Open(device);

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

        }

        public void ReadCaptureFile(string name)
        {


            var ver = Pcap.SharpPcapVersion;

            /* Print SharpPcap version */
            Console.WriteLine("SharpPcap {0}, ReadingCaptureFile", ver);
            Console.WriteLine();

            Console.WriteLine();

            // read the file from stdin or from the command line arguments
            string capFile;
            //if (args.Length == 0)
            //{
            //    Console.Write("-- Please enter an input capture file name: ");
            //    capFile = Console.ReadLine();
            //}
            //else
            //{
            //    // use the first argument as the filename
            //    capFile = name;
            //}

            capFile = name;

            Console.WriteLine("opening '{0}'", capFile);

            ICaptureDevice device;

            try
            {
                // Get an offline device
                device = new CaptureFileReaderDevice(capFile);

                // Open the device
                device.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine("Caught exception when opening file" + e.ToString());
                return;
            }

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            Console.WriteLine();
            Console.WriteLine
                ("-- Capturing from '{0}', hit 'Ctrl-C' to exit...",
                capFile);

            var startTime = DateTime.Now;

            // Start capture 'INFINTE' number of packets
            // This method will return when EOF reached.
            device.Capture();

            // Close the pcap device
            device.Close();
            var endTime = DateTime.Now;
            Console.WriteLine("-- End of file reached.");

            var duration = endTime - startTime;
            Console.WriteLine("Read {0} packets in {1}s", packetIndex, duration.TotalSeconds);

            Console.Write("Hit 'Enter' to exit...");
            Console.ReadLine();
        }

        private static int packetIndex = 0;

        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        //private static void device_OnPacketArrival(object sender, PacketCapture e)
        //{
        //    //var device = (ICaptureDevice)sender;

        //    // write the packet to the file
        //    var rawPacket = e.GetPacket();
        //    captureFileWriter.Write(rawPacket);
        //    Console.WriteLine("Packet dumped to file.");

        //    if (rawPacket.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
        //    {
        //        var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        //        var ethernetPacket = (EthernetPacket)packet;

        //        Console.WriteLine("{0} At: {1}:{2}: MAC:{3} -> MAC:{4}",
        //                          packetIndex,
        //                          rawPacket.Timeval.Date.ToString(),
        //                          rawPacket.Timeval.Date.Millisecond,
        //                          ethernetPacket.SourceHardwareAddress,
        //                          ethernetPacket.DestinationHardwareAddress);
        //        packetIndex++;
        //    }
        //}

        class PacketStatistics
        {
            public double AvgIpt { get; set; }
            public int BytesIn { get; set; }
            public int BytesOut { get; set; }
            public string DestIp { get; set; }
            public int DestPort { get; set; }
            public double Entropy { get; set; }
            public int NumPktsOut { get; set; }
            public int NumPktsIn { get; set; }
            public string Proto { get; set; }
            public string SrcIp { get; set; }
            public int SrcPort { get; set; }
            public DateTime TimeEnd { get; set; }
            public DateTime TimeStart { get; set; }
            public double TotalEntropy { get; set; }
            public double Duration => (TimeEnd - TimeStart).TotalSeconds;
        }


        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            // Write the packet to the file
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            Console.WriteLine("Packet dumped to file.");

            if (rawPacket.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            {
                var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ethernetPacket = packet.Extract<EthernetPacket>();

                // Check if the packet contains an IP packet
                //var ipPacket = PacketDotNet.IpPacket.GetEncapsulated(packet);

                PrintType(packet);
            }

                //if (packet is IPPacket)
                //{
                //    Console.WriteLine("The packet is an IP packet.");
                //}


                //    if (ethernetPacket != null)
                //    {
                //        Console.WriteLine("{0} At: {1}:{2}: MAC:{3} -> MAC:{4}",
                //                          packetIndex,
                //                          e.Header.Timeval.Date.ToString(),
                //                          e.Header.Timeval.Date.Millisecond,
                //                          ethernetPacket.SourceHardwareAddress,
                //                          ethernetPacket.DestinationHardwareAddress);
                //    }
                //}

                //if (ipPacket != null)
                //{
                //    var srcIp = ipPacket.SourceAddress.ToString();
                //    var destIp = ipPacket.DestinationAddress.ToString();
                //    var protocol = (int)ipPacket.Protocol;

                //    // Determine src and dest ports if applicable
                //    int srcPort = 0, destPort = 0;
                //    if (ipPacket is PacketDotNet.TcpPacket tcpPacket)
                //    {
                //        srcPort = tcpPacket.SourcePort;
                //        destPort = tcpPacket.DestinationPort;
                //    }
                //    else if (ipPacket is PacketDotNet.UdpPacket udpPacket)
                //    {
                //        srcPort = udpPacket.SourcePort;
                //        destPort = udpPacket.DestinationPort;
                //    }

                //    // Find or create a flow entry
                //    var flow = packetFlows.FirstOrDefault(pf => pf.SrcIp == srcIp && pf.DestIp == destIp && pf.SrcPort == srcPort && pf.DestPort == destPort && pf.Protocol == protocol);
                //    if (flow == null)
                //    {
                //        flow = new PacketFlow
                //        {
                //            SrcIp = srcIp,
                //            DestIp = destIp,
                //            SrcPort = srcPort,
                //            DestPort = destPort,
                //            Protocol = protocol,
                //            TimeStart = rawPacket.Timeval.Seconds * 1000000 + rawPacket.Timeval.MicroSeconds,
                //            TimeEnd = rawPacket.Timeval.Seconds * 1000000 + rawPacket.Timeval.MicroSeconds,
                //            NumPktsIn = 0,
                //            NumPktsOut = 0,
                //            BytesIn = 0,
                //            BytesOut = 0,
                //            TotalEntropy = 0,
                //            Label = "unknown" // Default label, you can modify it as needed
                //        };
                //        packetFlows.Add(flow);
                //    }

                //    // Update the flow entry
                //    long packetTime = rawPacket.Timeval.Seconds * 1000000 + rawPacket.Timeval.MicroSeconds;
                //    double packetEntropy = CalculateEntropy(rawPacket.Data); // Implement entropy calculation

                //    flow.TimeEnd = packetTime;
                //    flow.TotalEntropy += packetEntropy;

                //    if (srcIp == flow.SrcIp)
                //    {
                //        flow.BytesOut += rawPacket.Data.Length;
                //        flow.NumPktsOut++;
                //    }
                //    else
                //    {
                //        flow.BytesIn += rawPacket.Data.Length;
                //        flow.NumPktsIn++;
                //    }

                //    // Calculate the average inter-packet time and other statistics
                //    flow.Duration = (flow.TimeEnd - flow.TimeStart) / 1000000.0;
                //    flow.AvgInterPacketTime = flow.Duration / (flow.NumPktsIn + flow.NumPktsOut);
                //    flow.Entropy = flow.TotalEntropy / (flow.NumPktsIn + flow.NumPktsOut);

                //    // Print out the updated flow information
                //    Console.WriteLine($"Flow updated: SrcIp={flow.SrcIp}, DestIp={flow.DestIp}, Protocol={flow.Protocol}, BytesIn={flow.BytesIn}, BytesOut={flow.BytesOut}");
                //}

                //packetIndex++;
        }

        // Евент хендлер чтобы читать пакет

        //private static void device_OnPacketArrival(object sender, PacketCapture e)
        //{
        //    packetIndex++;

        //    var rawPacket = e.GetPacket();
        //    var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        //    var ethernetPacket = packet.Extract<EthernetPacket>();
        //    if (ethernetPacket != null)
        //    {
        //        Console.WriteLine("{0} At: {1}:{2}: MAC:{3} -> MAC:{4}",
        //                          packetIndex,
        //                          e.Header.Timeval.Date.ToString(),
        //                          e.Header.Timeval.Date.Millisecond,
        //                          ethernetPacket.SourceHardwareAddress,
        //                          ethernetPacket.DestinationHardwareAddress);
        //    }
        //}

        public static void PrintType(Packet packet)
        {
            if (packet is EthernetPacket ethernetPacket)
            {
                Console.WriteLine("The packet is an Ethernet packet.");

                if (ethernetPacket.PayloadPacket is IPPacket ipPacket)
                {
                    Console.WriteLine("The packet is an IP packet.");

                    if (ipPacket is IPv4Packet)
                    {
                        Console.WriteLine("The packet is an IPv4 packet.");
                    }
                    else if (ipPacket is IPv6Packet)
                    {
                        Console.WriteLine("The packet is an IPv6 packet.");
                    }

                    // Check for TCP or UDP packet within the IP packet
                    if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                    {
                        Console.WriteLine("The packet is a TCP packet.");
                        Console.WriteLine($"Source Port: {tcpPacket.SourcePort}, Destination Port: {tcpPacket.DestinationPort}");
                    }
                    else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        Console.WriteLine("The packet is a UDP packet.");
                        Console.WriteLine($"Source Port: {udpPacket.SourcePort}, Destination Port: {udpPacket.DestinationPort}");
                    }
                    else
                    {
                        Console.WriteLine("The IP packet's payload is not TCP or UDP.");
                    }
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

                if (ipPacketDirect is IPv4Packet)
                {
                    Console.WriteLine("The packet is an IPv4 packet.");
                }
                else if (ipPacketDirect is IPv6Packet)
                {
                    Console.WriteLine("The packet is an IPv6 packet.");
                }

                // Check for TCP or UDP packet within the IP packet
                if (ipPacketDirect.PayloadPacket is TcpPacket tcpPacket)
                {
                    Console.WriteLine("The packet is a TCP packet.");
                    Console.WriteLine($"Source Port: {tcpPacket.SourcePort}, Destination Port: {tcpPacket.DestinationPort}");
                }
                else if (ipPacketDirect.PayloadPacket is UdpPacket udpPacket)
                {
                    Console.WriteLine("The packet is a UDP packet.");
                    Console.WriteLine($"Source Port: {udpPacket.SourcePort}, Destination Port: {udpPacket.DestinationPort}");
                }
                else
                {
                    Console.WriteLine("The IP packet's payload is not TCP or UDP.");
                }
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

    }
}
