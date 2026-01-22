using CommandLine;

namespace ARP_Scanner;

[Verb("scan", true, HelpText = "Scan the specified IP range.")]
internal class ScanOptions
{
    [Value(0, Required = false, MetaName = "IP range", HelpText = "The IP range to scan.")]
    public string? IpRange { get; set; }

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

    [Option("auto", Required = false, HelpText = "Automatically scan all local IPv4 subnets when no IP range is specified.")]
    public bool AutoDiscover { get; set; }

    [Option("vendor", Required = false, HelpText = "Filter results by vendor name (case-insensitive substring).")]
    public string? VendorFilter { get; set; }

    [Option("mac-prefix", Required = false, HelpText = "Filter results by MAC prefix (e.g., 00:11:22).")]
    public string? MacPrefixFilter { get; set; }
}