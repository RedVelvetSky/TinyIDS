using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using CsvHelper;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Spectre.Console;
using TinyIDS.Utils;

namespace TinyIDS.Services
{
    public enum CaptureMode
    {
        Csv,
        Cap,
        Flow
    }

    public enum Verbosity
    {
        None,
        Basic,
        Detailed
    }

    public class PacketCaptureService
    {
        private ICaptureDevice _device;
        private static CaptureFileWriterDevice captureFileWriter;
        private static StreamWriter csvWriter;
        private static CsvWriter csv;
        private Verbosity _verbosity;
        private CaptureMode _captureMode;

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


        public void PrintSharpPcapVersion()
        {
            var ver = Pcap.SharpPcapVersion;
            Log($"SharpPcap {ver}", Verbosity.Basic);
        }

        private LibPcapLiveDeviceList GetDevices()
        {
            return LibPcapLiveDeviceList.Instance;
        }

        private void DisplayAvailableDevices(LibPcapLiveDeviceList devices)
        {
            Log("The following devices are available on this machine:", Verbosity.Basic);
            for (int i = 0; i < devices.Count; i++)
            {
                var dev = devices[i];
                Log($"{i}) {dev.Name} {dev.Description}", Verbosity.Basic);
            }
        }

        public void StartCapture(Verbosity verbosity, CaptureMode captureMode)
        {
            _verbosity = verbosity;
            _captureMode = captureMode;

            Log("Starting capture...", Verbosity.Basic);

            // Print SharpPcap version
            PrintSharpPcapVersion();

            // Retrieve the device list
            var devices = GetDevices();

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
            Console.Write("-- Please enter the CSV file name: ");
            string csvFile = Console.ReadLine();

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

            csvWriter = new StreamWriter(csvFile);
            csv = new CsvWriter(csvWriter, CultureInfo.InvariantCulture);

            csv.WriteHeader<PacketRecord>();
            csv.NextRecord();

            // Start the capturing process
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();
            captureFileWriter.Close();
            csvWriter.Close();

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

        private static void device_OnPacketArrivalCapture(object sender, PacketCapture e)
        {
            // Write the packet to the file
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);

            Console.WriteLine("\n------");
            Console.WriteLine("Packet dumped to file.");

            if (rawPacket.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            {
                var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ethernetPacket = packet.Extract<EthernetPacket>();

                if (ethernetPacket != null)
                {
                    var ipPacket = ethernetPacket.Extract<IPPacket>();
                    var tcpPacket = ipPacket?.Extract<TcpPacket>();
                    var udpPacket = ipPacket?.Extract<UdpPacket>();

                    var record = new PacketRecord
                    {
                        Timestamp = rawPacket.Timeval.Date.ToString("o"),
                        SourceMac = ethernetPacket.SourceHardwareAddress.ToString(),
                        DestinationMac = ethernetPacket.DestinationHardwareAddress.ToString(),
                        Protocol = ipPacket?.Protocol.ToString(),
                        SourceIp = ipPacket?.SourceAddress.ToString(),
                        DestinationIp = ipPacket?.DestinationAddress.ToString(),
                        SourcePort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort,
                        DestinationPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort,
                        Length = rawPacket.Data.Length,
                        Ttl = ipPacket?.TimeToLive,
                        SynFlag = tcpPacket != null ? tcpPacket.Synchronize : (bool?)null,
                        AckFlag = tcpPacket != null ? tcpPacket.Acknowledgment : (bool?)null,
                        FinFlag = tcpPacket != null ? tcpPacket.Finished : (bool?)null,
                        RstFlag = tcpPacket != null ? tcpPacket.Reset : (bool?)null,
                        WindowSize = tcpPacket?.WindowSize,
                        Payload = BitConverter.ToString(rawPacket.Data)
                    };

                    csv.WriteRecord(record);
                    csv.NextRecord();
                    csv.Flush();
                }

                PacketUtils.PrintType(packet);
            }
        }

        private void Log(string message, Verbosity requiredVerbosity)
        {
            if (_verbosity >= requiredVerbosity)
            {
                Console.WriteLine(message);
            }
        }
    }
}
