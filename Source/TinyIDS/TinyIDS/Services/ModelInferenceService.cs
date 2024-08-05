using System;
using Microsoft.ML;
using Microsoft.ML.Data;
using Spectre.Console;

namespace TinyIDS.Services
{
    internal class ModelInferenceService
    {
        private readonly string _modelPath;
        private readonly MLContext _mlContext;
        private ITransformer _loadedModel;
        private PredictionEngine<PacketData, Prediction> _predictionEngine;

        public ModelInferenceService(ITransformer trainedModel)
        {
            _mlContext = new MLContext();

            // Create a PredictionEngine from the trained model
            _predictionEngine = _mlContext.Model.CreatePredictionEngine<PacketData, Prediction>(trainedModel);

            AnsiConsole.MarkupLine("[green]Model initialized for inference.[/]");
        }

        private void LoadModel()
        {
            if (!System.IO.File.Exists(_modelPath))
            {
                AnsiConsole.MarkupLine($"[red]Model file not found at path: {_modelPath}[/red]");
                return;
            }

            try
            {
                // Load the trained model
                DataViewSchema modelSchema;
                _loadedModel = _mlContext.Model.Load(_modelPath, out modelSchema);
                _predictionEngine = _mlContext.Model.CreatePredictionEngine<PacketData, Prediction>(_loadedModel);

                AnsiConsole.MarkupLine("[green]Model loaded successfully.[/]");
            }
            catch (Exception ex)
            {
                // Log detailed information about the exception
                AnsiConsole.MarkupLine($"[red]Failed to load model: {ex.Message}[/]");
                AnsiConsole.MarkupLine($"[red]Stack Trace: {ex.StackTrace}[/]");
                if (ex.InnerException != null)
                {
                    AnsiConsole.MarkupLine($"[red]Inner Exception: {ex.InnerException.Message}[/]");
                }
            }
        }

        public void Predict(PacketData packetData)
        {
            try
            {
                var prediction = _predictionEngine.Predict(packetData);

                string result = prediction.PredictedLabel ? "Malicious" : "Non-Malicious";
                string color = prediction.PredictedLabel ? "red" : "green"; // Red for malicious, green for non-malicious

                AnsiConsole.MarkupLine($"[yellow]Prediction:[/] [{color}]{result}[/]");
                AnsiConsole.MarkupLine($"[yellow]Score:[/] {prediction.Score}");
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Prediction failed: {ex.Message}[/red]");
            }
        }
    }

    // Data model class for the output prediction
    public class Prediction
    {
        [ColumnName("PredictedLabel")]
        public bool PredictedLabel { get; set; }
        public float Score { get; set; }
    }
}
