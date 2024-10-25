using ArpLookup;

using CommandLine;

using CuteUtils.Misc;

using Humanizer;

using NetTools;

using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace ARP_Scanner;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (!Arp.IsSupported)
        {
            ConsoleExt.WriteLine("ARP is not supported on this platform!", ConsoleColor.Red);
            return 1;
        }

        return await Parser.Default.ParseArguments<ScanOptions>(args)
            .MapResult(StartScan, HandleParseError);
    }

    private static async Task<int> StartScan(ScanOptions options)
    {
        if (!IPAddressRange.TryParse(options.IpRange, out IPAddressRange ipAddressRange))
        {
            ConsoleExt.WriteLine("Invalid IP range!", ConsoleColor.Red);
            return 2;
        }

        MacVendorLookup macVendorLookup = new MacVendorLookup();
        await macVendorLookup.Initialize(options.Silent);

        long ipAddressesCount = ipAddressRange.Count();
        long processedIpAddressesCount = 0;
        int numberOfDigits = ipAddressesCount.ToString().Length;
        int exitCode = 0;


        ConcurrentBag<string[]> activeHosts = [];

        // If you want to change the header, you also need to change the JsonResult class
        List<string> header = [
            "IP",
            "MAC",
            nameof(MacInformation.VendorName).Humanize(LetterCasing.Title),
            nameof(MacInformation.BlockType).Humanize(LetterCasing.Title),
            nameof(MacInformation.Private).Humanize(LetterCasing.Title),
            nameof(MacInformation.LastUpdate).Humanize(LetterCasing.Title)];

        if (!options.Silent)
        {
            ConsoleExt.WriteLine("Starting scan...", ConsoleColor.DarkYellow);
        }

        ParallelOptions parallelOptions = new()
        {
            MaxDegreeOfParallelism = options.Concurrency
        };

        await Parallel.ForEachAsync(ipAddressRange, parallelOptions, async (IPAddress ipAddress, CancellationToken _) =>
        {
            PhysicalAddress? mac = null;
            bool fail = false;
            int retry = options.Retry;
            do
            {
                try
                {
                    mac = await Arp.LookupAsync(ipAddress);
                    fail = false;
                }
                catch (Exception ex)
                {
                    if (!options.Silent)
                    {
                        ConsoleExt.WriteLine($"Failed to lookup MAC address for {ipAddress}: {ex.Message}", ConsoleColor.Red);
                    }
                    fail = true;
                }
            }
            while (retry-- > 0 && (mac is null || fail));

            long localProcessedIpAddressesCount = Interlocked.Increment(ref processedIpAddressesCount);
            if (mac is not null && Array.Exists(mac.GetAddressBytes(), b => b != 0))
            {
                string formattedMac = BitConverter.ToString(mac.GetAddressBytes());

                MacInformation macInformation = macVendorLookup.GetInformation(formattedMac);

                List<string> info = [ipAddress.ToString(), formattedMac, macInformation.VendorName, macInformation.BlockType, macInformation.Private.ToString() ?? "Unknown", macInformation.LastUpdate];
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] |   Active: {ipAddress}", ConsoleColor.Green);
                }
                activeHosts.Add([.. info]);
            }
            else if (fail)
            {
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] |   Failed: {ipAddress}", ConsoleColor.Red);
                }
            }
            else
            {
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] | Inactive: {ipAddress}", ConsoleColor.Red);
                }
            }
        });

        if (!options.Silent)
        {
            Console.WriteLine();
        }

        List<string[]>? activeHostsTable = [.. activeHosts];
        activeHostsTable.Insert(0, [.. header]);

        if (!activeHosts.IsEmpty)
        {
            Console.WriteLine($"Active host{(activeHosts.Count == 1 ? "s" : "")}:");

            activeHostsTable.ToArray().To2D().PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {"active host".ToQuantity(activeHosts.Count)}", ConsoleColor.Green);
        }
        else if (!options.Silent)
        {
            ConsoleExt.WriteLine($"No active hosts found", ConsoleColor.Red);
        }

        if (!options.Silent && (options.JsonPath is not null || options.CsvPath is not null))
        {
            Console.WriteLine();
        }

        if (options.JsonPath is not null)
        {
            try
            {
                File.WriteAllText(options.JsonPath, JsonSerializer.Serialize(JsonResult.Parse([.. activeHosts])));

                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Saved JSON to '{options.JsonPath}'", ConsoleColor.Green);
                }
            }
            catch (Exception ex)
            {
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Failed to save JSON to '{options.JsonPath}': {ex.Message}", ConsoleColor.Red);
                }

                exitCode = 3;
            }
        }

        if (options.CsvPath is not null)
        {
            try
            {
                File.WriteAllLines(options.CsvPath, activeHostsTable.Select(row => string.Join(",", row)));

                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Saved CSV to '{options.CsvPath}'", ConsoleColor.Green);
                }
            }
            catch (Exception ex)
            {
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Failed to save CSV to '{options.CsvPath}': {ex.Message}", ConsoleColor.Red);
                }

                exitCode = 3;
            }
        }

        return exitCode;
    }

    private static Task<int> HandleParseError(IEnumerable<Error> errors)
    {
        if (errors.IsHelp() || errors.IsVersion())
        {
            return Task.FromResult(0);
        }
        else
        {
            return Task.FromResult(1);
        }
    }
}