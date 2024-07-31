using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TinyIDS.Utils
{
    public enum Verbosity
    {
        None,
        Basic,
        Detailed
    }

    public class Logger
    {
        private readonly Verbosity _verbosity;

        public Logger(Verbosity verbosity)
        {
            _verbosity = verbosity;
        }

        public void Log(string message, Verbosity requiredVerbosity)
        {
            if (_verbosity >= requiredVerbosity)
            {
                AnsiConsole.MarkupLine(message);
            }
        }

        public void LogDeviceStatistics(string statistics)
        {
            //AnsiConsole.Write(new Panel(statistics)
            //    .Header("Device Statistics")
            //    .Border(BoxBorder.Rounded)
            //    .BorderColor(Color.Grey)
            //    .Expand());

            Console.WriteLine(statistics);
        }
    }
}
