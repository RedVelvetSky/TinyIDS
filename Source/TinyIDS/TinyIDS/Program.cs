using System;
using Spectre.Console;
using TinyIDS.Services;


namespace TinyIDS
{
    class Program
    {
        static void Main(string[] args)
        {
            AnsiConsole.Markup("[bold green]Intrusion Detection System Starting...[/]\n");

            // Create an instance of the ModelTrainingService
            //var modelTrainingService = new ModelTrainingService();

            // Train and save the model
            //modelTrainingService.TrainAndSaveModel();

            //Console.WriteLine("Model training completed. Press any key to exit...");
            //Console.ReadKey();

            //var modelInferenceService = new ModelInferenceService();

            // Example input data for prediction
            //var inputData = new PacketData {};

            //var prediction = modelInferenceService.Predict(inputData);

            //AnsiConsole.MarkupLine($"[bold yellow]Predicted Label: {prediction.PredictedLabel}[/]");
            //AnsiConsole.MarkupLine($"[bold yellow]Scores: {string.Join(", ", prediction.Score)}[/]");

            var packetCaptureService = new PacketCaptureService();

            //packetCaptureService.ListDevices();

            packetCaptureService.StartCapture();

            //packetCaptureService.ReadCaptureFile("E:\\Stuff\\IDS Machine Learning\\Source\\TinyIDS\\TinyIDS\\bin\\Debug\\net7.0\\test");

        }
    }
}