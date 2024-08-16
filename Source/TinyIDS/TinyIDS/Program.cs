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
                new TextPrompt<string>("What mode of IDS to use? [green]Train[/], [green]Capture[/] or [green]Read[/]")
                    .PromptStyle("yellow")
                    .DefaultValue("capture")
                    .Validate(input =>
                    input.Equals("Capture", StringComparison.OrdinalIgnoreCase) ||
                    input.Equals("Train", StringComparison.OrdinalIgnoreCase) ||
                    input.Equals("Read", StringComparison.OrdinalIgnoreCase)
                        ? ValidationResult.Success()
                        : ValidationResult.Error("[red]Invalid mode. Please enter 'Train' or 'Capture'.[/]")
                )
            );

            AnsiConsole.WriteLine();

            // Prompt for dataset path and model save path if in Train mode
            string dataPath = "";
            string modelPath = "";

            if (mode.Equals("Train", StringComparison.OrdinalIgnoreCase) || mode.Equals("capture", StringComparison.OrdinalIgnoreCase))
            {
                dataPath = AnsiConsole.Prompt(
                    new TextPrompt<string>("Enter the path for the training dataset:")
                        .PromptStyle("yellow")
                        .DefaultValue("..\\..\\..\\Dataset\\Train\\train.csv")
                );

                modelPath = AnsiConsole.Prompt(
                    new TextPrompt<string>("Enter the path to save the trained model:")
                        .PromptStyle("yellow")
                        .DefaultValue(".\\model.zip")
                );
            }

            AnsiConsole.WriteLine();

            // Prompt for verbosity level
            var verbosity = AnsiConsole.Prompt(
                new SelectionPrompt<Utils.Verbosity>()
                    .Title("Choose verbosity level:")
                    .AddChoices(Utils.Verbosity.None, Utils.Verbosity.Basic, Utils.Verbosity.Detailed)
                    .UseConverter(v => v.ToString())
            );

            AnsiConsole.WriteLine();

            

            // Handling the selected mode
            switch (mode.ToLower())
            {
                case "capture":
                    // Initialize services for Capture mode
                    var packetCaptureService = new PacketCaptureService(verbosity);
                    var captureModeModelTrainingService = new ModelTrainingService(dataPath: dataPath, modelPath: modelPath);

                    // Prompt for capture mode
                    var captureMode = AnsiConsole.Prompt(
                        new SelectionPrompt<CaptureMode>()
                            .Title("Choose capture mode:")
                            .AddChoices(CaptureMode.Csv, CaptureMode.Cap, CaptureMode.Flow)
                            .UseConverter(c => c.ToString())
                    );

                    AnsiConsole.Markup($"[bold yellow]Capture mode selected: {captureMode}. Proceeding with data capture...[/]\n");

                    packetCaptureService.StartCapture(captureMode);
                    break;
                case "read":
                    // Prompt for file path to read
                    var filePath = AnsiConsole.Prompt(
                        new TextPrompt<string>("Enter the path of the file to read:")
                            .PromptStyle("yellow")
                    );

                    AnsiConsole.Markup("[bold yellow]Read mode selected. Proceeding with reading the capture file...[/]\n");

                    var readService = new PacketReadService(verbosity); // Initialize the correct service
                    readService.ReadCaptureFile(filePath);
                    break;

                case "train":
                    // Initialize services for Train mode
                    var trainModeModelTrainingService = new ModelTrainingService(dataPath: dataPath, modelPath: modelPath);

                    AnsiConsole.Markup("[bold yellow]Train mode selected. Proceeding with training...[/]\n");
                    // Train the model
                    var trainedModel = trainModeModelTrainingService.TrainModel();
                    break;
                default:
                    // Initialize services for Default mode (Flow)
                    var defaultPacketCaptureService = new PacketCaptureService(verbosity);
                    var defaultModeModelTrainingService = new ModelTrainingService(dataPath: dataPath, modelPath: modelPath);

                    AnsiConsole.Markup("[bold yellow]Default mode selected. Proceeding with Flow capture...[/]\n");
                    defaultPacketCaptureService.StartCapture(CaptureMode.Flow);
                    break;
            }
        }
    }
}