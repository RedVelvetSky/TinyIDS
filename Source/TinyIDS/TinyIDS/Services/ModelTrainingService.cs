using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;
using Spectre.Console;


namespace TinyIDS.Services
{
    internal class ModelTrainingService
    {
        private readonly string TrainDataPath = "E:\\Stuff\\IDS Machine Learning\\Dataset\\Train_data.csv"; // потом поменять
        private readonly string TestDataPath = "E:\\Stuff\\IDS Machine Learning\\Dataset\\Test_data.csv"; // потом поменять
        private readonly string ModelPath = "E:\\Stuff\\IDS Machine Learning\\Source\\TinyIDS\\TinyIDS\\model.zip"; // потом поменять

        public void TrainAndSaveModel()
        {
            var mlContext = new MLContext(seed: 0);

            AnsiConsole.MarkupLine("[bold yellow]Loading and preprocessing data...[/]");

            // load and preprocess data
            //var trainData = mlContext.Data.LoadFromTextFile<PacketData>(TrainDataPath, separatorChar: ',', hasHeader: true);
            //var testData = mlContext.Data.LoadFromTextFile<PacketData>(TestDataPath, separatorChar: ',', hasHeader: true);

            var data = mlContext.Data.LoadFromTextFile<PacketData>(TrainDataPath, separatorChar: ',', hasHeader: true);

            AnsiConsole.MarkupLine("[bold yellow]Data loaded successfully![/]");

            // Split the data into training and validation sets
            var trainTestData = mlContext.Data.TrainTestSplit(data, testFraction: 0.2);
            var trainData = trainTestData.TrainSet;
            var validationData = trainTestData.TestSet;

            // define data transofmration
            var dataProcessPipeline = mlContext.Transforms.Conversion.MapValueToKey(nameof(PacketData.Label))
                .Append(mlContext.Transforms.Categorical.OneHotEncoding(nameof(PacketData.ProtocolType)))
                .Append(mlContext.Transforms.Categorical.OneHotEncoding(nameof(PacketData.Service)))
                .Append(mlContext.Transforms.Categorical.OneHotEncoding(nameof(PacketData.Flag)))
                .Append(mlContext.Transforms.Concatenate("Features",
                    nameof(PacketData.Duration),
                    nameof(PacketData.ProtocolType),
                    nameof(PacketData.Service),
                    nameof(PacketData.Flag),
                    nameof(PacketData.SrcBytes),
                    nameof(PacketData.DstBytes),
                    nameof(PacketData.Land),
                    nameof(PacketData.WrongFragment),
                    nameof(PacketData.Urgent),
                    nameof(PacketData.Hot),
                    nameof(PacketData.NumFailedLogins),
                    nameof(PacketData.LoggedIn),
                    nameof(PacketData.NumCompromised),
                    nameof(PacketData.RootShell),
                    nameof(PacketData.SuAttempted),
                    nameof(PacketData.NumRoot),
                    nameof(PacketData.NumFileCreations),
                    nameof(PacketData.NumShells),
                    nameof(PacketData.NumAccessFiles),
                    nameof(PacketData.NumOutboundCmds),
                    nameof(PacketData.IsHostLogin),
                    nameof(PacketData.IsGuestLogin),
                    nameof(PacketData.Count),
                    nameof(PacketData.SrvCount),
                    nameof(PacketData.SerrorRate),
                    nameof(PacketData.SrvSerrorRate),
                    nameof(PacketData.RerrorRate),
                    nameof(PacketData.SrvRerrorRate),
                    nameof(PacketData.SameSrvRate),
                    nameof(PacketData.DiffSrvRate),
                    nameof(PacketData.SrvDiffHostRate),
                    nameof(PacketData.DstHostCount),
                    nameof(PacketData.DstHostSrvCount),
                    nameof(PacketData.DstHostSameSrvRate),
                    nameof(PacketData.DstHostDiffSrvRate),
                    nameof(PacketData.DstHostSameSrcPortRate),
                    nameof(PacketData.DstHostSrvDiffHostRate),
                    nameof(PacketData.DstHostSerrorRate),
                    nameof(PacketData.DstHostSrvSerrorRate),
                    nameof(PacketData.DstHostRerrorRate),
                    nameof(PacketData.DstHostSrvRerrorRate)))
                .Append(mlContext.Transforms.NormalizeMinMax("Features"));

            //// Define the trainer
            //var trainer = mlContext.BinaryClassification.Trainers.FastForest();

            //var trainingPipeline = dataProcessPipeline.Append(trainer)
            //                                          .Append(mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel"));

            // Define the trainer
            var trainer = mlContext.MulticlassClassification.Trainers.OneVersusAll(mlContext.BinaryClassification.Trainers.FastForest(), labelColumnName: "Label")
                .Append(mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel"));

            var trainingPipeline = dataProcessPipeline.Append(trainer);

            // Train the model with a progress bar
            AnsiConsole.Progress()
                .Start(ctx =>
                {
                    var task = ctx.AddTask("[green]Training the model...[/]");

                    task.MaxValue = 100;
                    for (int i = 0; i < 100; i++)
                    {
                        // Simulate some work by sleeping the thread
                        System.Threading.Thread.Sleep(50);
                        task.Increment(1);
                    }

                    // Train the model
                    var trainedModel = trainingPipeline.Fit(trainData);

                    task.StopTask();

                    // Evaluate the model on train data
                    var trainMetrics = mlContext.MulticlassClassification.Evaluate(trainedModel.Transform(trainData));
                    AnsiConsole.MarkupLine($"[bold yellow]Train Data - Log-loss: {trainMetrics.LogLoss}[/]");
                    AnsiConsole.MarkupLine($"[bold yellow]Train Data - MicroAccuracy: {trainMetrics.MicroAccuracy}[/]");
                    AnsiConsole.MarkupLine($"[bold yellow]Train Data - MacroAccuracy: {trainMetrics.MacroAccuracy}[/]");

                    // Evaluate the model on validation data
                    var validationMetrics = mlContext.MulticlassClassification.Evaluate(trainedModel.Transform(validationData), labelColumnName: "Label");
                    AnsiConsole.MarkupLine($"[bold yellow]Validation Data - Log-loss: {validationMetrics.LogLoss}[/]");
                    AnsiConsole.MarkupLine($"[bold yellow]Validation Data - MicroAccuracy: {validationMetrics.MicroAccuracy}[/]");
                    AnsiConsole.MarkupLine($"[bold yellow]Validation Data - MacroAccuracy: {validationMetrics.MacroAccuracy}[/]");

                    // Save the model
                    mlContext.Model.Save(trainedModel, trainData.Schema, ModelPath);
                    AnsiConsole.MarkupLine("[bold green]Model saved to " + ModelPath + "[/]");
                });
        }
    }

    public class PacketData
    {
        [LoadColumn(0)]
        public float Duration { get; set; }

        [LoadColumn(1)]
        public string ProtocolType { get; set; }

        [LoadColumn(2)]
        public string Service { get; set; }

        [LoadColumn(3)]
        public string Flag { get; set; }

        [LoadColumn(4)]
        public float SrcBytes { get; set; }

        [LoadColumn(5)]
        public float DstBytes { get; set; }

        [LoadColumn(6)]
        public float Land { get; set; }

        [LoadColumn(7)]
        public float WrongFragment { get; set; }

        [LoadColumn(8)]
        public float Urgent { get; set; }

        [LoadColumn(9)]
        public float Hot { get; set; }

        [LoadColumn(10)]
        public float NumFailedLogins { get; set; }

        [LoadColumn(11)]
        public float LoggedIn { get; set; }

        [LoadColumn(12)]
        public float NumCompromised { get; set; }

        [LoadColumn(13)]
        public float RootShell { get; set; }

        [LoadColumn(14)]
        public float SuAttempted { get; set; }

        [LoadColumn(15)]
        public float NumRoot { get; set; }

        [LoadColumn(16)]
        public float NumFileCreations { get; set; }

        [LoadColumn(17)]
        public float NumShells { get; set; }

        [LoadColumn(18)]
        public float NumAccessFiles { get; set; }

        [LoadColumn(19)]
        public float NumOutboundCmds { get; set; }

        [LoadColumn(20)]
        public float IsHostLogin { get; set; }

        [LoadColumn(21)]
        public float IsGuestLogin { get; set; }

        [LoadColumn(22)]
        public float Count { get; set; }

        [LoadColumn(23)]
        public float SrvCount { get; set; }

        [LoadColumn(24)]
        public float SerrorRate { get; set; }

        [LoadColumn(25)]
        public float SrvSerrorRate { get; set; }

        [LoadColumn(26)]
        public float RerrorRate { get; set; }

        [LoadColumn(27)]
        public float SrvRerrorRate { get; set; }

        [LoadColumn(28)]
        public float SameSrvRate { get; set; }

        [LoadColumn(29)]
        public float DiffSrvRate { get; set; }

        [LoadColumn(30)]
        public float SrvDiffHostRate { get; set; }

        [LoadColumn(31)]
        public float DstHostCount { get; set; }

        [LoadColumn(32)]
        public float DstHostSrvCount { get; set; }

        [LoadColumn(33)]
        public float DstHostSameSrvRate { get; set; }

        [LoadColumn(34)]
        public float DstHostDiffSrvRate { get; set; }

        [LoadColumn(35)]
        public float DstHostSameSrcPortRate { get; set; }

        [LoadColumn(36)]
        public float DstHostSrvDiffHostRate { get; set; }

        [LoadColumn(37)]
        public float DstHostSerrorRate { get; set; }

        [LoadColumn(38)]
        public float DstHostSrvSerrorRate { get; set; }

        [LoadColumn(39)]
        public float DstHostRerrorRate { get; set; }

        [LoadColumn(40)]
        public float DstHostSrvRerrorRate { get; set; }

        [LoadColumn(41)]
        public string Label { get; set; }
    }
}
