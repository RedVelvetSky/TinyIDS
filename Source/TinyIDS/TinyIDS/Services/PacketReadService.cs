using System;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Spectre.Console;
using TinyIDS.Utils;

namespace TinyIDS.Services
{
    public class PacketReadService
    {
        private static int packetIndex = 0;
        private static Logger _logger;

        public PacketReadService(Verbosity verbosity)
        {
            _logger = new Logger(verbosity);
        }

        public void ReadCaptureFile(string name)
        {
            ICaptureDevice device;

            PrintSharpPcapVersion();
            string capFile = name;
            AnsiConsole.MarkupLine($"[bold]Opening '{capFile}'[/]");

            try
            {
                device = new CaptureFileReaderDevice(capFile);

                device.Open();
                device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrivalRead);
                AnsiConsole.MarkupLine($"-- Capturing from '[bold yellow]{capFile}[/]', hit 'Ctrl-C' to exit...");

                var startTime = DateTime.Now;
                device.Capture();
                device.Close();

                var endTime = DateTime.Now;
                AnsiConsole.MarkupLine("[bold]-- End of file reached.[/]");
                var duration = endTime - startTime;
                AnsiConsole.MarkupLine($"Read [bold]{packetIndex}[/] packets in [bold]{duration.TotalSeconds}[/]s");

                AnsiConsole.Markup("[bold]Hit 'Enter' to exit...[/]");
                Console.ReadLine();
            }
            catch (Exception e)
            {
                AnsiConsole.MarkupLine("[bold red]Caught exception when opening file: [/]" + e);
            }
        }

        private static void device_OnPacketArrivalRead(object sender, PacketCapture e)
        {
            packetIndex++;

            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                AnsiConsole.MarkupLine($"{packetIndex} At: [bold]{e.Header.Timeval.Date.ToString()}[/]:{e.Header.Timeval.Date.Millisecond}: MAC:{ethernetPacket.SourceHardwareAddress} -> MAC:{ethernetPacket.DestinationHardwareAddress}");
            }
        }

        private void PrintSharpPcapVersion()
        {
            var ver = Pcap.SharpPcapVersion;
            _logger.Log($"Using SharpPcap {ver}", Verbosity.Basic);
        }
    }
}
