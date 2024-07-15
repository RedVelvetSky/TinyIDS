using System;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using Spectre.Console;

namespace TinyIDS.Services
{
    public class PacketCaptureService
    {
        private readonly ICaptureDevice device;

        public PacketCaptureService()
        {
            // Select the first available device
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                throw new InvalidOperationException("No devices were found on this machine.");
            }

            device = devices[0];
            device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);
        }

        public void StartCapture()
        {
            device.Open(DeviceMode.Promiscuous);
            device.StartCapture();
            AnsiConsole.MarkupLine("[bold green]Packet capture started...[/]");
        }

        public void StopCapture()
        {
            device.StopCapture();
            device.Close();
            AnsiConsole.MarkupLine("[bold red]Packet capture stopped.[/]");
        }

        private void OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var ipPacket = packet.Extract<IpPacket>();

            if (ipPacket != null)
            {
                AnsiConsole.MarkupLine("[bold yellow]Packet Structure:[/]");
                AnsiConsole.MarkupLine($"[bold blue]IP Source: {ipPacket.SourceAddress}[/]");
                AnsiConsole.MarkupLine($"[bold blue]IP Destination: {ipPacket.DestinationAddress}[/]");

                if (tcpPacket != null)
                {
                    PrintTcpPacket(tcpPacket);
                }
                else if (udpPacket != null)
                {
                    PrintUdpPacket(udpPacket);
                }
            }
        }

        private void PrintTcpPacket(TcpPacket tcpPacket)
        {
            AnsiConsole.MarkupLine("[bold yellow]TCP Packet:[/]");
            AnsiConsole.MarkupLine($"[bold blue]Source Port: {tcpPacket.SourcePort}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Destination Port: {tcpPacket.DestinationPort}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Sequence Number: {tcpPacket.SequenceNumber}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Acknowledgment Number: {tcpPacket.AcknowledgmentNumber}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Data Offset: {tcpPacket.DataOffset}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Flags: {tcpPacket.Flags}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Window Size: {tcpPacket.WindowSize}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Urgent Pointer: {tcpPacket.UrgentPointer}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Payload Data Length: {tcpPacket.PayloadData.Length}[/]");
        }

        private void PrintUdpPacket(UdpPacket udpPacket)
        {
            AnsiConsole.MarkupLine("[bold yellow]UDP Packet:[/]");
            AnsiConsole.MarkupLine($"[bold blue]Source Port: {udpPacket.SourcePort}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Destination Port: {udpPacket.DestinationPort}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Length: {udpPacket.Length}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Checksum: {udpPacket.Checksum}[/]");
            AnsiConsole.MarkupLine($"[bold blue]Payload Data Length: {udpPacket.PayloadData.Length}[/]");
        }
    }
}
