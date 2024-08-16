using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers.FastTree;
using Microsoft.ML.Transforms;
using Spectre.Console;

namespace TinyIDS.Services
{
    internal class ModelTrainingService
    {
        private readonly string _dataPath;
        private readonly string _modelPath;

        public ModelTrainingService(string dataPath, string modelPath)
        {
            _dataPath = dataPath;
            _modelPath = modelPath;
        }

        public ITransformer TrainModel()
        {
            // Initialize ML.NET environment
            var mlContext = new MLContext();

            // Load data from a text file or any other source
            IDataView dataView = mlContext.Data.LoadFromTextFile<PacketData>(
                path: _dataPath,
                hasHeader: true,
                separatorChar: ',');

            // Split data into training and validation datasets
            var splitData = mlContext.Data.TrainTestSplit(dataView, testFraction: 0.2);
            var trainData = splitData.TrainSet;
            var testData = splitData.TestSet;

            // Identify top 30 most frequent DestinationPort values
            var top30Ports = trainData.GetColumn<float>("DestinationPort")
                                     .GroupBy(x => x)
                                     .OrderByDescending(g => g.Count())
                                     .Take(30)
                                     .Select(g => g.Key)
                                     .ToArray();

            // Custom mapping for DestinationPort - top 30 will be kept, others set to "Other"
            var dataProcessPipeline = mlContext.Transforms.CustomMapping<PacketData, MappedData>(
                (input, output) => {
                    output.Protocol = input.Protocol;
                    output.DestinationPort = top30Ports.Contains(input.DestinationPort)
                                             ? input.DestinationPort.ToString()
                                             : "Other";
                    output.Length = input.Length;
                    output.Ttl = input.Ttl;
                    output.SynFlag = input.SynFlag ? 1.0f : 0.0f;
                    output.AckFlag = input.AckFlag ? 1.0f : 0.0f;
                    output.FinFlag = input.FinFlag ? 1.0f : 0.0f;
                    output.RstFlag = input.RstFlag ? 1.0f : 0.0f;
                    output.WindowSize = input.WindowSize;
                    output.PayloadSize = input.PayloadSize;
                    output.Entropy = input.Entropy;
                    output.IsMalicious = input.IsMalicious;
                }, contractName: "MapPortsAndFlags")
                .Append(mlContext.Transforms.CopyColumns("Label", "IsMalicious"))
                .Append(mlContext.Transforms.Categorical.OneHotEncoding(
                    new[]
                    {
                    new InputOutputColumnPair("ProtocolEncoded", "Protocol"),
                    new InputOutputColumnPair("DestinationPortEncoded", "DestinationPort")
                    }))
                .Append(mlContext.Transforms.Concatenate("Features",
                    "ProtocolEncoded",
                    "DestinationPortEncoded",
                    "Length",
                    "Ttl",
                    "SynFlag",
                    "AckFlag",
                    "FinFlag",
                    "RstFlag",
                    "WindowSize",
                    "PayloadSize",
                    "Entropy"))
                .Append(mlContext.Transforms.NormalizeMinMax("Features"))
                .AppendCacheCheckpoint(mlContext);

            // Set the FastForest trainer
            var trainer = mlContext.BinaryClassification.Trainers.FastForest(
                new FastForestBinaryTrainer.Options
                {
                    NumberOfTrees = 100,
                    NumberOfLeaves = 20,
                    MinimumExampleCountPerLeaf = 10,
                    FeatureFraction = 0.7
                });

            // Create the training pipeline
            var trainingPipeline = dataProcessPipeline
                .Append(trainer);

            // Train the model
            var model = trainingPipeline.Fit(trainData);

            // Evaluate the model on the validation dataset
            EvaluateModel(mlContext, model, testData, "Validation");

            // Evaluate the model on the training dataset
            EvaluateModel(mlContext, model, trainData, "Training");

            // Save the model after training
            //SaveModel(model, trainData.Schema);

            // Block the thread for 5 seconds
            Thread.Sleep(3000);

            // Clear the screen
            AnsiConsole.Clear();

            return model;
        }

        public void SaveModel(ITransformer model, DataViewSchema modelSchema)
        {
            var mlContext = new MLContext();
            try
            {
                mlContext.Model.Save(model, modelSchema, _modelPath);
                AnsiConsole.MarkupLine($"[green]Model saved successfully to {_modelPath}[/]");
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Failed to save the model: {ex.Message}[/]");
            }
        }

        // Method to evaluate the model and print metrics
        private static void EvaluateModel(MLContext mlContext, ITransformer model, IDataView data, string datasetName)
        {
            var predictions = model.Transform(data);
            var metrics = mlContext.BinaryClassification.EvaluateNonCalibrated(predictions, "Label", scoreColumnName: "Score", predictedLabelColumnName: "PredictedLabel");

            // Create a table to display the metrics
            var table = new Table()
                .AddColumn(new TableColumn("[yellow]Metric[/]").Centered())
                .AddColumn(new TableColumn("[yellow]Value[/]").Centered());

            // Add rows for each metric
            table.AddRow("[green]Accuracy[/]", $"[bold]{metrics.Accuracy:P2}[/]");
            table.AddRow("[green]AUC[/]", $"[bold]{metrics.AreaUnderRocCurve:P2}[/]");
            table.AddRow("[green]F1 Score[/]", $"[bold]{metrics.F1Score:P2}[/]");

            // Create a panel to encapsulate the table with a title
            var panel = new Panel(table)
            {
                Border = BoxBorder.Rounded,
                Header = new PanelHeader($"[bold yellow]Metrics for {datasetName} Dataset[/]", Justify.Center),
                Padding = new Padding(1, 1),
            };

            // Display the panel
            AnsiConsole.Write(panel);

            // Optionally add a blank line for spacing
            AnsiConsole.WriteLine();
        }

        public class MappedData
        {
            public string Protocol { get; set; }
            public string DestinationPort { get; set; }
            public float Length { get; set; }
            public float Ttl { get; set; }
            public float SynFlag { get; set; }
            public float AckFlag { get; set; }
            public float FinFlag { get; set; }
            public float RstFlag { get; set; }
            public float WindowSize { get; set; }
            public float PayloadSize { get; set; }
            public float Entropy { get; set; }
            public bool IsMalicious { get; set; }
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

}