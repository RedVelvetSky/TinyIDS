using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using CsvHelper;
using PacketDotNet;
using PcapDotNet.Packets;
using SharpPcap;
using SharpPcap.LibPcap;
using Spectre.Console;
using TinyIDS.Models;
using TinyIDS.Utils;

namespace TinyIDS.Services
{
    public enum CaptureMode
    {
        Csv,
        Cap,
        Flow
    }

    public class PacketCaptureService
    {
        private ICaptureDevice _device;
        private static CaptureFileWriterDevice captureFileWriter;
        private static StreamWriter csvWriter;
        private static CsvWriter csv;
        private static Verbosity _verbosity;
        private CaptureMode _captureMode;
        private static PacketProcessor _packetProcessor;
        private static Logger _logger;

        public PacketCaptureService(Verbosity verbosity)
        {
            _logger = new Logger(verbosity);
            _packetProcessor = new PacketProcessor(_logger, "E:\\Stuff\\IDS Machine Learning\\Dataset\\Train\\train.csv");
        }

        public void ListDevices()
        {
            var devices = CaptureDeviceList.Instance;

            if (devices.Count == 0)
            {
                AnsiConsole.MarkupLine("[bold red]No interfaces found! Make sure WinPcap or Npcap is installed.[/]");
                return;
            }

            var table = new Table();
            table.AddColumn("Name");
            table.AddColumn("Description");

            foreach (var device in devices)
            {
                table.AddRow(device.Name, device.Description);
            }

            AnsiConsole.Write(table);
        }


        public void PrintSharpPcapVersion()
        {
            var ver = Pcap.SharpPcapVersion;
            Log($"Using SharpPcap {ver}", Verbosity.Basic);
        }

        private LibPcapLiveDeviceList GetDevices()
        {
            return LibPcapLiveDeviceList.Instance;
        }

        private void DisplayAvailableDevices(LibPcapLiveDeviceList devices)
        {
            var table = new Table();
            table.AddColumn(new TableColumn("[bold]Index[/]").Centered());
            table.AddColumn(new TableColumn("[bold]Name[/]").Centered());
            table.AddColumn(new TableColumn("[bold]Description[/]").Centered());

            for (int i = 0; i < devices.Count; i++)
            {
                var dev = devices[i];
                table.AddRow(i.ToString(), dev.Name, dev.Description);
            }

            AnsiConsole.Write(table);
        }

        private int GetDeviceIndexFromUser()
        {
            return AnsiConsole.Prompt(
                new TextPrompt<int>("[bold]Please choose a device to capture on[/]:")
                    .PromptStyle("green")
                    .Validate(index =>
                        index >= 0 ? ValidationResult.Success() : ValidationResult.Error("[red]Invalid device index[/]")));
        }

        private string GetOutputFileNameFromUser(string fileType)
        {
            return AnsiConsole.Ask<string>($"[bold]Please enter the {fileType} file name[/]:");
        }

        public void StartCapture(CaptureMode captureMode)
        {
            _captureMode = captureMode;

            Log("Starting capture...", Verbosity.Basic);

            // Print SharpPcap version
            PrintSharpPcapVersion();

            // Retrieve the device list
            var devices = GetDevices();

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                AnsiConsole.MarkupLine("[bold red]No devices were found on this machine[/]");
                return;
            }

            DisplayAvailableDevices(devices);

            int deviceIndex = GetDeviceIndexFromUser();
            string capFile = null;
            string csvFile = null;

            if (_captureMode == CaptureMode.Cap)
            {
                capFile = GetOutputFileNameFromUser("capture");
            }

            if (_captureMode == CaptureMode.Csv)
            {
                csvFile = GetOutputFileNameFromUser("CSV");
            }

            CapturePackets(devices[deviceIndex], capFile, csvFile);
        }

        private void CapturePackets(ICaptureDevice device, string capFile, string csvFile)
        {
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrivalCapture);
            device.Open(DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: 1000);

            Log($"Listening on [bold yellow]{device.Description}[/], writing to [bold green]{capFile}[/], hit 'Enter' to stop...", Verbosity.Basic);

            if (_captureMode == CaptureMode.Cap && capFile != null)
            {
                captureFileWriter = new CaptureFileWriterDevice(capFile);
                captureFileWriter.Open(device);
            }

            if (_captureMode == CaptureMode.Csv && csvFile != null)
            {
                csvWriter = new StreamWriter(csvFile);
                csv = new CsvWriter(csvWriter, CultureInfo.InvariantCulture);
                csv.WriteHeader<PacketRecord>();
                csv.NextRecord();
            }

            device.StartCapture();
            if (_verbosity >= Verbosity.Detailed)
            {
                Console.WriteLine();
                AnsiConsole.Write(
                 new Rule("[bold green]Detailed information about packets:[/]")
                     .RuleStyle("green")
                     .Centered());
                Console.WriteLine();

            }
            Console.ReadLine();
            device.StopCapture();

            if (_captureMode == CaptureMode.Cap && captureFileWriter != null)
            {
                captureFileWriter.Close();
            }

            if (_captureMode == CaptureMode.Csv && csvWriter != null)
            {
                csvWriter.Close();
            }

            Log("[bold green]Capture stopped.[/]", Verbosity.Basic);
            LogDeviceStatistics(device.Statistics.ToString());
        }

        private static void device_OnPacketArrivalCapture(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();

            _packetProcessor.ProcessPacket(rawPacket);

            if (captureFileWriter != null)
            {
                captureFileWriter.Write(rawPacket);
            }

            if (rawPacket.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            {
                var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ethernetPacket = packet.Extract<EthernetPacket>();
                //PacketUtils.PrintType(packet);

                if (ethernetPacket != null)
                {
                    var ipPacket = ethernetPacket.Extract<IPPacket>();
                    var tcpPacket = ipPacket?.Extract<TcpPacket>();
                    var udpPacket = ipPacket?.Extract<UdpPacket>();

                    LogPacketInfo(packet, Verbosity.Detailed);
                    var record = FeatureExtractor.ExtractFeatures(rawPacket);
                    

                    if (csv != null)
                    {
                        csv.WriteRecord(record);
                        csv.NextRecord();
                        csv.Flush();
                    }
                }

                
            }
        }

        private void Log(string message, Verbosity requiredVerbosity)
        {
            _logger.Log(message, requiredVerbosity);
        }

        private void LogDeviceStatistics(string statistics)
        {
            _logger.LogDeviceStatistics(statistics);
        }

        public static void LogPacketInfo(PacketDotNet.Packet packet, Verbosity requiredVerbosity)
        {
            _logger.LogPacketInfo(packet, requiredVerbosity);
        }
    }
}
