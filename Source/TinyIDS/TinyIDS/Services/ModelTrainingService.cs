using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Transforms;
using Spectre.Console;

namespace TinyIDS.Services
{
    internal class ModelTrainingService
    {
        private readonly string TrainDataPath = "E:\\Stuff\\IDS Machine Learning\\Dataset\\Train\\train.csv";
        private readonly string ModelPath = "E:\\Stuff\\IDS Machine Learning\\Source\\TinyIDS\\TinyIDS\\model.zip";

        private readonly List<int> ExploitedPorts = new List<int> { 19, 135, 137, 138, 139, 445, 1433, 1720, 1900, 2323, 4444, 5555, 6666, 6667, 6668, 6669, 11211, 12345, 31337, 54321 };

        public void TrainAndSaveModel()
        {
            var mlContext = new MLContext(seed: 0);

            AnsiConsole.MarkupLine("[bold yellow]Loading and preprocessing data...[/]");

            // Load data
            var data = mlContext.Data.LoadFromTextFile<PacketData>(TrainDataPath, separatorChar: ',', hasHeader: true);
            AnsiConsole.MarkupLine("[bold yellow]Data loaded successfully![/]");

            // Split the data into training and validation sets
            var trainTestData = mlContext.Data.TrainTestSplit(data, testFraction: 0.2);
            var trainData = trainTestData.TrainSet;
            var validationData = trainTestData.TestSet;

            // Identify the top 10 most frequent ports not in the exploited ports list
            var top10Ports = GetTop10Ports(mlContext, trainData, ExploitedPorts);

            // Define the data transformation pipeline
            var dataProcessPipeline = mlContext.Transforms.CustomMapping<PacketData, PortEncodingOutput>((input, output) =>
            {
                // Ensure that EncodedPort is treated as a string
                if (ExploitedPorts.Contains((int)input.DestinationPort))
                {
                    output.EncodedPort = $"ExploitedPort_{input.DestinationPort}";
                }
                else if (top10Ports.Contains((int)input.DestinationPort))
                {
                    output.EncodedPort = $"TopPort_{input.DestinationPort}";
                }
                else
                {
                    output.EncodedPort = "Other";
                }
            }, "PortEncoding")
            .Append(mlContext.Transforms.Conversion.ConvertType(nameof(PortEncodingOutput.EncodedPort), outputKind: DataKind.String))
            .Append(mlContext.Transforms.Categorical.OneHotEncoding(outputColumnName: "EncodedPortOneHot", inputColumnName: nameof(PortEncodingOutput.EncodedPort)))
            .Append(mlContext.Transforms.Concatenate("Flags", nameof(PacketData.SynFlag), nameof(PacketData.AckFlag), nameof(PacketData.FinFlag), nameof(PacketData.RstFlag)))
            .Append(mlContext.Transforms.Concatenate("Features",
                nameof(PacketData.Protocol),
                "EncodedPortOneHot",  // Ensure this is used correctly after conversion and encoding
                "Flags",
                nameof(PacketData.Length),
                nameof(PacketData.Ttl),
                nameof(PacketData.WindowSize),
                nameof(PacketData.PayloadSize),
                nameof(PacketData.Entropy)))
            .Append(mlContext.Transforms.NormalizeMinMax("Features"));



            // Define the trainer
            var trainer = mlContext.BinaryClassification.Trainers.FastForest(labelColumnName: nameof(PacketData.IsMalicious))
                .Append(mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel"));

            var trainingPipeline = dataProcessPipeline.Append(trainer);

            // Train the model
            var trainedModel = trainingPipeline.Fit(trainData);

            // Evaluate the model on train data
            var trainMetrics = mlContext.BinaryClassification.Evaluate(trainedModel.Transform(trainData));
            AnsiConsole.MarkupLine($"[bold yellow]Train Data - Accuracy: {trainMetrics.Accuracy}[/]");
            AnsiConsole.MarkupLine($"[bold yellow]Train Data - F1 Score: {trainMetrics.F1Score}[/]");
            AnsiConsole.MarkupLine($"[bold yellow]Train Data - AUC: {trainMetrics.AreaUnderRocCurve}[/]");

            // Evaluate the model on validation data
            var validationMetrics = mlContext.BinaryClassification.Evaluate(trainedModel.Transform(validationData));
            AnsiConsole.MarkupLine($"[bold yellow]Validation Data - Accuracy: {validationMetrics.Accuracy}[/]");
            AnsiConsole.MarkupLine($"[bold yellow]Validation Data - F1 Score: {validationMetrics.F1Score}[/]");
            AnsiConsole.MarkupLine($"[bold yellow]Validation Data - AUC: {validationMetrics.AreaUnderRocCurve}[/]");

            // Save the model
            mlContext.Model.Save(trainedModel, trainData.Schema, ModelPath);
            AnsiConsole.MarkupLine("[bold green]Model saved to " + ModelPath + "[/]");
        }

        private List<int> GetTop10Ports(MLContext mlContext, IDataView dataView, List<int> excludedPorts)
        {
            // Extract the destination port column
            var portColumn = mlContext.Data.CreateEnumerable<PacketData>(dataView, reuseRowObject: false)
                                             .Select(p => (int)p.DestinationPort)
                                             .Where(port => !excludedPorts.Contains(port));

            // Get the top 10 most frequent ports that are not in the exploited ports list
            var top10Ports = portColumn.GroupBy(port => port)
                                       .OrderByDescending(g => g.Count())
                                       .Take(10)
                                       .Select(g => g.Key)
                                       .ToList();

            return top10Ports;
        }
    }

    public class PacketData
    {
        [LoadColumn(0)]
        public string Protocol { get; set; }

        [LoadColumn(1)]
        public float DestinationPort { get; set; }

        [LoadColumn(2)]
        public float Length { get; set; }

        [LoadColumn(3)]
        public float Ttl { get; set; }

        [LoadColumn(4)]
        public bool SynFlag { get; set; }

        [LoadColumn(5)]
        public bool AckFlag { get; set; }

        [LoadColumn(6)]
        public bool FinFlag { get; set; }

        [LoadColumn(7)]
        public bool RstFlag { get; set; }

        [LoadColumn(8)]
        public float WindowSize { get; set; }

        [LoadColumn(9)]
        public float PayloadSize { get; set; }

        [LoadColumn(10)]
        public float Entropy { get; set; }

        [LoadColumn(11)]
        public bool IsMalicious { get; set; }
    }

    public class PortEncodingOutput
    {
        public string EncodedPort { get; set; }
    }

    public class CustomMappingOutput
    {
        [ColumnName("EncodedPortMapped")]
        public string EncodedPortMapped { get; set; }
    }

    [CustomMappingFactoryAttribute("PortEncodingMapping")]
    public class PortEncodingMapping : CustomMappingFactory<PortEncodingOutput, CustomMappingOutput>
    {
        public static void CustomMapping(PortEncodingOutput input, CustomMappingOutput output)
        {
            // Here we ensure that EncodedPort is properly converted to a string if needed
            output.EncodedPortMapped = input.EncodedPort;
        }

        public override Action<PortEncodingOutput, CustomMappingOutput> GetMapping()
            => CustomMapping;
    }
}
