# TinyIDS: A Lightweight Intrusion Detection System

TinyIDS is a lightweight Intrusion Detection System (IDS) implemented in C#. It uses machine learning to detect potentially malicious network traffic by capturing, processing, and analyzing network packets.

**USE ONLY FOR THE PURPOSE OF FUN AND EDUCATION. NOT SUITABLE FOR ANY KIND OF PRODUCTION.**

## Features

- **Packet Capture**: Captures network packets using the SharpPcap library and processes them for analysis.
- **Machine Learning Integration**: Uses ML.NET to train and infer a model for detecting malicious packets.
- **Multiple Modes**: Operates in different modes, including training, capturing, and reading packet data.
- **Command-Line Interface**: Utilizes Spectre.Console for a user-friendly command-line interface with interactive prompts.

## Project Structure

- **`Program.cs`**: The entry point of the application. Handles user input and starts the appropriate IDS mode.
- **`PacketCaptureService.cs`**: Manages packet capturing using different modes (CSV, Cap, Flow).
- **`ModelTrainingService.cs`**: Handles the training of the machine learning model using packet data.
- **`ModelInferenceService.cs`**: Provides the inference capabilities to predict whether a packet is malicious.
- **`PacketProcessor.cs`**: Processes captured packets, extracts features, and utilizes the trained model for prediction.
- **`FeatureExtractor.cs`**: Extracts features from packets to be used in model training and inference.

## Getting Started

### Prerequisites

- .NET SDK (version 6.0 or higher)
- [SharpPcap](https://github.com/chmorgan/sharppcap) for packet capturing
- [ML.NET](https://dotnet.microsoft.com/apps/machinelearning-ai/ml-dotnet) for machine learning
- [Spectre.Console](https://spectreconsole.net/) for command-line interface

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/TinyIDS.git
   ```
2. Navigate to the project directory:
   ```bash
   cd TinyIDS
   ```
3. Restore dependencies:
    ```bash
    dotnet restore
    ```
    
### Running the Application
1. Start the IDS:
    ```bash
    dotnet run
    ```
2. **Choose a mode**: When prompted, choose either `Train`, `Capture`, or `Read`.

   - **Train**: This mode trains a machine learning model using the provided dataset. The trained model can then be used for real-time packet analysis.
     - **Steps**:
       1. When prompted, select `Train`.
       2. The system will load the training data from the specified path.
       3. The training process will begin, and the model will be evaluated on the validation dataset.
       4. Once training is complete, the model will be saved to the specified location.

   - **Capture**: This mode captures live network traffic using a selected network interface. The captured data can be saved in CSV or Cap file format.
     - **Steps**:
       1. Select `Capture` when prompted.
       2. Choose the network interface to capture packets from.
       3. Select the output format (`CSV` or `Cap`).
       4. The application will begin capturing packets. You can stop the capture by pressing `Enter`.

   - **Read**: This mode allows you to read and analyze previously captured packet data from a file.
     - **Steps**:
       1. Select `Read` mode.
       2. Provide the path to the captured file (e.g., a Cap file).
       3. The system will process the file and analyze the packets, outputting the results to the console.

## Configuration

- The paths to the dataset and model files are currently hard-coded in the source code. You can modify these paths in the relevant service classes:
  - **Training Data Path**: Modify in `ModelTrainingService.cs`.
  - **Model Path**: Modify in `ModelTrainingService.cs` and `ModelInferenceService.cs`.

## Example Usage

1. **Training the Model**:
   - Choose the `Train` mode.
   - The system will process the training data and evaluate the model.
   - The trained model will be saved to the specified file path.

2. **Capturing Network Traffic**:
   - Choose `Capture` mode.
   - Select a network interface and output format.
   - The captured packets will be saved in the selected format.

3. **Reading from a Capture File**:
   - Choose `Read` mode.
   - Provide the file path to a previously captured packet file.
   - The system will analyze the packets and display the results.

## Contributing

Contributions are welcome! If you have any improvements, suggestions, or find any issues, feel free to open an issue or submit a pull request. Please make sure to follow the code of conduct when contributing to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [SharpPcap](https://github.com/chmorgan/sharppcap) - Packet capturing library.
- [ML.NET](https://dotnet.microsoft.com/apps/machinelearning-ai/ml-dotnet) - Machine learning library.
- [Spectre.Console](https://spectreconsole.net/) - Command-line interface library.
