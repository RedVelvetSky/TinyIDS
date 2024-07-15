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
            var modelTrainingService = new ModelTrainingService();

            // Train and save the model
            //modelTrainingService.TrainAndSaveModel();

            //Console.WriteLine("Model training completed. Press any key to exit...");
            //Console.ReadKey();

            var modelInferenceService = new ModelInferenceService();

            // Example input data for prediction
            var inputData = new PacketData
            {
                Duration = 0,
                ProtocolType = "tcp",
                Service = "http",
                Flag = "SF",
                SrcBytes = 232,
                DstBytes = 8153,
                Land = 0,
                WrongFragment = 0,
                Urgent = 0,
                Hot = 0,
                NumFailedLogins = 0,
                LoggedIn = 1,
                NumCompromised = 0,
                RootShell = 0,
                SuAttempted = 0,
                NumRoot = 0,
                NumFileCreations = 0,
                NumShells = 0,
                NumAccessFiles = 0,
                NumOutboundCmds = 0,
                IsHostLogin = 0,
                IsGuestLogin = 0,
                Count = 5,
                SrvCount = 5,
                SerrorRate = 0.2f,
                SrvSerrorRate = 0.2f,
                RerrorRate = 0,
                SrvRerrorRate = 0,
                SameSrvRate = 1,
                DiffSrvRate = 0,
                SrvDiffHostRate = 0,
                DstHostCount = 30,
                DstHostSrvCount = 255,
                DstHostSameSrvRate = 1,
                DstHostDiffSrvRate = 0,
                DstHostSameSrcPortRate = 0.03f,
                DstHostSrvDiffHostRate = 0.04f,
                DstHostSerrorRate = 0.03f,
                DstHostSrvSerrorRate = 0.01f,
                DstHostRerrorRate = 0,
                DstHostSrvRerrorRate = 0
            };

            var prediction = modelInferenceService.Predict(inputData);

            AnsiConsole.MarkupLine($"[bold yellow]Predicted Label: {prediction.PredictedLabel}[/]");
            AnsiConsole.MarkupLine($"[bold yellow]Scores: {string.Join(", ", prediction.Score)}[/]");
        }
    }
}