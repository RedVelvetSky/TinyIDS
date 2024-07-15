using System;
using Microsoft.ML;
using Microsoft.ML.Data;
using Spectre.Console;

namespace TinyIDS.Services
{
    internal class ModelInferenceService
    {
        private readonly string ModelPath = "E:\\Stuff\\IDS Machine Learning\\Source\\TinyIDS\\TinyIDS\\model.zip";
        private readonly MLContext mlContext;
        private ITransformer trainedModel;
        private PredictionEngine<PacketData, PacketPrediction> predictionEngine;

        public ModelInferenceService()
        {
            mlContext = new MLContext();
            LoadModel();
        }

        private void LoadModel()
        {
            AnsiConsole.MarkupLine("[bold yellow]Loading the model...[/]");
            DataViewSchema modelSchema;
            trainedModel = mlContext.Model.Load(ModelPath, out modelSchema);
            predictionEngine = mlContext.Model.CreatePredictionEngine<PacketData, PacketPrediction>(trainedModel);
            AnsiConsole.MarkupLine("[bold green]Model loaded successfully![/]");
        }

        public PacketPrediction Predict(PacketData inputData)
        {
            AnsiConsole.MarkupLine("[bold yellow]Making prediction...[/]");
            var prediction = predictionEngine.Predict(inputData);
            AnsiConsole.MarkupLine("[bold green]Prediction completed![/]");
            return prediction;
        }
    }

    public class PacketPrediction
    {
        [ColumnName("PredictedLabel")]
        public string PredictedLabel { get; set; }

        public float[] Score { get; set; }
    }
}
