using CommandLine;

namespace ARP_Scanner;

[Verb("monitor", HelpText = "Continuously monitor the specified IP range.")]
internal class MonitorOptions : ScanOptions
{
    [Option('d', "delay", Required = false, Default = 60, HelpText = "The delay between each scan in seconds.")]
    public int Delay { get; set; }
}