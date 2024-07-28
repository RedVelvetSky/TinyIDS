using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TinyIDS.Utils
{
    public class PacketRecord
    {
        public string Timestamp { get; set; }
        public string SourceMac { get; set; }
        public string DestinationMac { get; set; }
        public string Protocol { get; set; }
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int? SourcePort { get; set; }
        public int? DestinationPort { get; set; }
        public int Length { get; set; }
        public int? Ttl { get; set; } // Time To Live
        public bool? SynFlag { get; set; } // SYN flag for TCP packets
        public bool? AckFlag { get; set; } // ACK flag for TCP packets
        public bool? FinFlag { get; set; } // FIN flag for TCP packets
        public bool? RstFlag { get; set; } // RST flag for TCP packets
        public int? WindowSize { get; set; } // TCP window size
        public string Payload { get; set; } // Packet payload
    }
}
