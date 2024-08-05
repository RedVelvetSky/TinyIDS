using SharpPcap;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TinyIDS.Models;
using TinyIDS.Utils;

namespace TinyIDS.Services
{
    public class PacketProcessor
    {
        private readonly int _maxPayloadSize;
        private readonly double _minEntropy;
        private readonly double _maxEntropy;
        private readonly Logger _logger;
        private readonly ModelInferenceService _modelInferenceService;

        private PacketData MapPacketRecordToPacketData(PacketRecord record)
        {
            return new PacketData
            {
                Protocol = record.Protocol,
                DestinationPort = record.DestinationPort.HasValue ? record.DestinationPort.Value : 0, // Handle nullable types
                Length = record.Length,
                Ttl = record.Ttl.HasValue ? record.Ttl.Value : 0,
                SynFlag = record.SynFlag.HasValue ? record.SynFlag.Value : false,
                AckFlag = record.AckFlag.HasValue ? record.AckFlag.Value : false,
                FinFlag = record.FinFlag.HasValue ? record.FinFlag.Value : false,
                RstFlag = record.RstFlag.HasValue ? record.RstFlag.Value : false,
                WindowSize = record.WindowSize.HasValue ? record.WindowSize.Value : 0,
                PayloadSize = record.PayloadSize,
                Entropy = (float)record.Entropy,
                IsMalicious = false // This will be ignored for predictions
            };
        }

        public PacketProcessor(Logger logger, string dataPath, int maxPayloadSize = 2000, double minEntropy = 0.5, double maxEntropy = 8.0)
        {
            _logger = logger;
            _maxPayloadSize = maxPayloadSize;
            _minEntropy = minEntropy;
            _maxEntropy = maxEntropy;

            // Train the model using ModelTrainingService
            var modelTrainingService = new ModelTrainingService(dataPath, null); // No need for a model path here
            var trainedModel = modelTrainingService.TrainModel();

            // Initialize the ModelInferenceService with the trained model instead of a model path
            _modelInferenceService = new ModelInferenceService(trainedModel);
        }

        public void ProcessPacket(RawCapture rawPacket)
        {
            // Extract features
            var record = FeatureExtractor.ExtractFeatures(rawPacket);

            //// Apply static filters
            //if (Filter.ApplyPayloadSizeFilter(record, _maxPayloadSize))
            //{
            //    _logger.Log($"[bold red]Rejected packet based on payload size filter (size: {record.Length})[/]", Verbosity.Basic);
            //    return;
            //}

            //if (Filter.ApplySuspiciousPortFilter(record))
            //{
            //    _logger.Log($"[bold red]Rejected packet based on suspicious port filter (src port: , dst port: {record.DestinationPort})[/]", Verbosity.Basic);
            //    return;
            //}

            //if (Filter.ApplyEntropyFilter(record, _minEntropy, _maxEntropy))
            //{
            //    _logger.Log($"[bold red]Rejected packet based on entropy filter (entropy: {record.Entropy})[/]", Verbosity.Basic);
            //    return;
            //}

            //if (Filter.ApplyAnomalyFilter(record))
            //{
            //    _logger.Log($"[bold red]Rejected packet based on anomaly filter[/]", Verbosity.Basic);
            //    return;
            //}

            // Convert PacketRecord to PacketData
            var packetData = MapPacketRecordToPacketData(record);

            // Make prediction using the loaded model
            Console.WriteLine();
            AnsiConsole.MarkupLine("[yellow]Making prediction for the packet...[/]");
            _modelInferenceService.Predict(packetData);
        }
    }
}
