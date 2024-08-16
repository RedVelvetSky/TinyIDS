using System;
using System.Linq.Expressions;
using Spectre.Console;
using TinyIDS.Services;


namespace TinyIDS
{
    class Program
    {
        static void Main(string[] args)
        {
            AnsiConsole.Markup("[blink yellow]Intrusion Detection System Starting...[/]\n");

            AnsiConsole.WriteLine();

            string mode = AnsiConsole.Prompt(
                new TextPrompt<string>("What mode of IDS to use? [green]Train[/] or [green]Capture[/]")
                    .PromptStyle("yellow")
                    .DefaultValue("capture as default")
                    .Validate(input =>
                    input.Equals("Capture", StringComparison.OrdinalIgnoreCase) ||
                    input.Equals("Train", StringComparison.OrdinalIgnoreCase) ||
                    input.Equals("Read", StringComparison.OrdinalIgnoreCase)
                        ? ValidationResult.Success()
                        : ValidationResult.Error("[red]Invalid mode. Please enter 'Train' or 'Capture'.[/]")
                )
            );

            AnsiConsole.WriteLine();

            var packetCaptureService = new PacketCaptureService(Utils.Verbosity.Detailed);
            var modelTrainingService = new TinyIDS.Services.ModelTrainingService(
                        dataPath: "..\\..\\..\\Dataset\\Train\\train.csv",
                        modelPath: ".\\model.zip"
                    );

            // Handling the selected mode
            switch (mode.ToLower())
            {
                case "capture":
                    AnsiConsole.Markup("[bold yellow]Capture mode selected. Proceeding with data capture...[/]\n");
                   
                    packetCaptureService.StartCapture(CaptureMode.Csv);
                    break;
                case "read":
                    AnsiConsole.Markup("[bold yellow]Capture mode selected. Proceeding with data capture...[/]\n");
                    //packetCaptureService.ReadCaptureFile("E:\\Stuff\\IDS Machine Learning\\Source\\TinyIDS\\TinyIDS\\bin\\Debug\\net7.0\\test");
                    break;
                case "train":
                    AnsiConsole.Markup("[bold yellow]Train mode selected. Proceeding with training...[/]\n");
                    // Train the model
                    var trainedModel = modelTrainingService.TrainModel();

                    // Optionally save the model
                    //modelTrainingService.SaveModel(trainedModel, trainedModel.GetOutputSchema());
                    break;
                default:
                    packetCaptureService.StartCapture(CaptureMode.Flow);
                    break;
            }


            

            

        }
    }
}

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