using CommandLine;

namespace ARP_Scanner;

[Verb("scan", HelpText = "Scan the specified IP range.")]
internal class ScanOptions
{
    [Value(0, Required = true, MetaName = "IP range", HelpText = "The IP range to scan.")]
    public required string IpRange { get; set; }

    [Option('s', "silent", Required = false, HelpText = "Don't print anything to the console.")]
    public bool Silent { get; set; }

    [Option('r', "retry", Required = false, Default = 0, HelpText = "The number of retries for each ARP request.")]
    public int Retry { get; set; }

    [Option('c', "concurrency", Required = false, Default = -1, HelpText = "The number of concurrent ARP requests.")]
    public int Concurrency { get; set; }

    [Option("json", Required = false, HelpText = "The path to the JSON file to save the results.")]
    public string? JsonPath { get; set; }

    [Option("csv", Required = false, HelpText = "The path to the CSV file to save the results.")]
    public string? CsvPath { get; set; }
}