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
                new PacketArrivalEventHandler(device_OnPacketArrivalCapture);

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
                new PacketArrivalEventHandler(device_OnPacketArrivalRead);

            Console.WriteLine();
            Console.WriteLine
                ("-- Capturing from '{0}', hit 'Ctrl-C' to exit...", capFile);

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
        /// Prints the time and length of each received packet (ORIGINAL CAPTURE VERSION)
        /// </summary>
        //private static void device_OnPacketArrivalCapture(object sender, PacketCapture e)
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

        //ORIGINAL READ VERSION
        private static void device_OnPacketArrivalRead(object sender, PacketCapture e)
        {
            packetIndex++;

            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                Console.WriteLine("{0} At: {1}:{2}: MAC:{3} -> MAC:{4}",
                                  packetIndex,
                                  e.Header.Timeval.Date.ToString(),
                                  e.Header.Timeval.Date.Millisecond,
                                  ethernetPacket.SourceHardwareAddress,
                                  ethernetPacket.DestinationHardwareAddress);
            }
        }

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

        private static void device_OnPacketArrivalCapture(object sender, PacketCapture e)
        {
            // Write the packet to the file
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            Console.WriteLine("Packet dumped to file.");

            if (rawPacket.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            {
                var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ethernetPacket = packet.Extract<EthernetPacket>();

                PrintType(packet);
            }
        }

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

    }


}
