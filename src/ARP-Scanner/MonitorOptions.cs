using CommandLine;

namespace ARP_Scanner;

[Verb("monitor", HelpText = "Continuously monitor the specified IP range.")]
internal class MonitorOptions : ScanOptions
{
    [Option('d', "delay", Required = false, Default = 60, HelpText = "The delay between each scan in seconds.")]
    public int Delay { get; set; }

    [Option("changes-only", Required = false, HelpText = "During monitoring, only print when hosts are added or removed.")]
    public bool ChangesOnly { get; set; }

    [Option("summary", Required = false, HelpText = "Print a compact summary after each scan instead of per-IP progress.")]
    public bool Summary { get; set; }

    [Option("on-new", Required = false, HelpText = "Command to execute when new hosts appear. Receives JSON on stdin.")]
    public string? OnNewCommand { get; set; }

    [Option("on-removed", Required = false, HelpText = "Command to execute when hosts disappear. Receives JSON on stdin.")]
    public string? OnRemovedCommand { get; set; }
}