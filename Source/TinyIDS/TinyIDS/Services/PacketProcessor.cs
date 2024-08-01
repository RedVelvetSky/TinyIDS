using SharpPcap;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TinyIDS.Utils;

namespace TinyIDS.Services
{
    public class PacketProcessor
    {
        private readonly int _maxPayloadSize;
        private readonly double _minEntropy;
        private readonly double _maxEntropy;
        private readonly Logger _logger;

        public PacketProcessor(Logger logger, int maxPayloadSize = 2000, double minEntropy = 0.5, double maxEntropy = 8.0)
        {
            _logger = logger;
            _maxPayloadSize = maxPayloadSize;
            _minEntropy = minEntropy;
            _maxEntropy = maxEntropy;
        }

        public void ProcessPacket(RawCapture rawPacket)
        {
            // Extract features
            var record = FeatureExtractor.ExtractFeatures(rawPacket);

            // Apply static filters
            if (Filter.ApplyPayloadSizeFilter(record, _maxPayloadSize))
            {
                _logger.Log($"[bold red]Rejected packet based on payload size filter (size: {record.Length})[/]", Verbosity.Basic);
                return;
            }

            if (Filter.ApplySuspiciousPortFilter(record))
            {
                _logger.Log($"[bold red]Rejected packet based on suspicious port filter (src port: , dst port: {record.DestinationPort})[/]", Verbosity.Basic);
                return;
            }

            if (Filter.ApplyEntropyFilter(record, _minEntropy, _maxEntropy))
            {
                _logger.Log($"[bold red]Rejected packet based on entropy filter (entropy: {record.Entropy})[/]", Verbosity.Basic);
                return;
            }

            if (Filter.ApplyAnomalyFilter(record))
            {
                _logger.Log($"[bold red]Rejected packet based on anomaly filter[/]", Verbosity.Basic);
                return;
            }
        }
    }
}
