using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TinyIDS.Utils
{
    public class PacketStatistics
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
}
