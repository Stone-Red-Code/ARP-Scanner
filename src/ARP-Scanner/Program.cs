using ArpLookup;

using CommandLine;

using CuteUtils.Misc;

using Humanizer;
using Humanizer.Localisation;

using NetTools;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ARP_Scanner;

internal static class Program
{
    private static readonly MacVendorLookup macVendorLookup = new();
    private static readonly List<string[]> previouslyActiveHosts = [];

    private static readonly JsonSerializerOptions jsonSerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static async Task<int> Main(string[] args)
    {
        if (!Arp.IsSupported)
        {
            ConsoleExt.WriteLine("ARP is not supported on this platform!", ConsoleColor.Red);
            return 1;
        }

        return await Parser.Default.ParseArguments<ScanOptions, MonitorOptions>(args)
            .MapResult(
            (MonitorOptions monitorOptions) => StartMonitor(monitorOptions),
            (ScanOptions scanOptions) => StartScan(scanOptions),
            HandleParseError);
    }

    private static async Task<int> StartMonitor(MonitorOptions options)
    {
        ConsoleExt.WriteLine($"Monitoring IP range '{options.IpRange}' every {options.Delay} seconds...", ConsoleColor.DarkYellow);

        while (true)
        {
            int exitCode = await StartScan(options);

            if (exitCode != 0)
            {
                return exitCode;
            }

            Console.WriteLine();

            Stopwatch stopwatch = Stopwatch.StartNew();

            bool printed = false;

            while (stopwatch.Elapsed < TimeSpan.FromSeconds(options.Delay))
            {
                TimeSpan remainingTime = TimeSpan.FromSeconds(options.Delay) - stopwatch.Elapsed;
                Console.Write($"\rNext scan in: {remainingTime.Humanize(3, minUnit: TimeUnit.Second)} ");
                await Task.Delay(1000);
                printed = true;
            }

            if (printed)
            {
                Console.Write($"\r{new string(' ', Console.WindowWidth)}\r");
            }
        }
    }

    private static async Task<int> StartScan(ScanOptions options)
    {
        if (!IPAddressRange.TryParse(options.IpRange, out IPAddressRange ipAddressRange))
        {
            ConsoleExt.WriteLine("Invalid IP range!", ConsoleColor.Red);
            return 2;
        }

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

                List<string> info = [ipAddress.ToString(), formattedMac, macInformation.VendorName, macInformation.BlockType, macInformation.Private?.ToString() ?? "Unknown", macInformation.LastUpdate];
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

        if (previouslyActiveHosts.Count > 0 && !options.Silent)
        {
            PrintDifference(activeHosts, header);
        }
        else if (!options.Silent)
        {
            PrintActiveHosts(activeHosts, header);
        }

        if (!options.Silent && (options.JsonPath is not null || options.CsvPath is not null))
        {
            Console.WriteLine();
        }

        if (options.JsonPath is not null)
        {
            string jsonPath = GetOutputPath(options.JsonPath, ".json");

            try
            {
                _ = Directory.CreateDirectory(Path.GetDirectoryName(jsonPath) ?? string.Empty);

                string json = JsonSerializer.Serialize(JsonResult.Parse([.. activeHosts], previouslyActiveHosts), jsonSerializerOptions);
                File.WriteAllText(jsonPath, json);

                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Saved JSON to '{jsonPath}'", ConsoleColor.Green);
                }
            }
            catch (Exception ex)
            {
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Failed to save JSON to '{jsonPath}': {ex.Message}", ConsoleColor.Red);
                }

                exitCode = 3;
            }
        }

        if (options.CsvPath is not null)
        {
            string csvPath = GetOutputPath(options.CsvPath, ".csv");
            List<string[]>? activeHostsTable = [.. activeHosts];
            activeHostsTable.Insert(0, [.. header]);

            try
            {
                _ = Directory.CreateDirectory(Path.GetDirectoryName(csvPath) ?? string.Empty);
                File.WriteAllLines(csvPath, activeHostsTable.Select(row => string.Join(",", row)));

                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Saved CSV to '{csvPath}'", ConsoleColor.Green);
                }
            }
            catch (Exception ex)
            {
                if (!options.Silent)
                {
                    ConsoleExt.WriteLine($"Failed to save CSV to '{csvPath}': {ex.Message}", ConsoleColor.Red);
                }

                exitCode = 3;
            }
        }

        previouslyActiveHosts.Clear();
        foreach (string[] activeHost in activeHosts)
        {
            previouslyActiveHosts.Add(activeHost);
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

    private static string GetOutputPath(string path, string extension)
    {
        string directory = Path.GetDirectoryName(path) ?? string.Empty;
        string fileName = Path.GetFileNameWithoutExtension(path);
        string fileExtension = Path.GetExtension(path);
        fileExtension = string.IsNullOrEmpty(fileExtension) ? extension : fileExtension;

        string dateTime = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");

        string newPath = Path.Combine(directory, $"{fileName}_{dateTime}{fileExtension}");

        int counter = 0;
        while (File.Exists(newPath))
        {
            newPath = Path.Combine(directory, $"{fileName}_{dateTime}_{++counter}{fileExtension}");
        }

        return newPath;
    }

    private static void PrintActiveHosts(ConcurrentBag<string[]> activeHosts, List<string> header)
    {
        List<string[]>? activeHostsTable = [.. activeHosts];
        activeHostsTable.Insert(0, [.. header]);

        Console.WriteLine();

        if (!activeHosts.IsEmpty)
        {
            Console.WriteLine($"Active hosts:");

            activeHostsTable.ToArray().To2D().PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {"active host".ToQuantity(activeHosts.Count)}", ConsoleColor.Green);
        }
        else
        {
            ConsoleExt.WriteLine($"No active hosts found", ConsoleColor.Red);
        }
    }

    private static void PrintDifference(ConcurrentBag<string[]> activeHosts, List<string> header)
    {
        List<string[]> newHosts = activeHosts.Where(activeHost => !previouslyActiveHosts.Exists(previousHost => previousHost[1] == activeHost[1])).ToList();
        List<string[]> removedHosts = previouslyActiveHosts.Where(previousHost => !activeHosts.Any(activeHost => activeHost[1] == previousHost[1])).ToList();

        List<string[]>? newHostsTable = [.. newHosts];
        newHostsTable.Insert(0, [.. header]);

        List<string[]>? removedHostsTable = [.. removedHosts];
        removedHostsTable.Insert(0, [.. header]);

        Console.WriteLine();

        if (newHosts.Count > 0)
        {
            Console.WriteLine($"New hosts:");

            newHostsTable.ToArray().To2D().PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {"active host".ToQuantity(activeHosts.Count)}", ConsoleColor.Green);
        }
        else
        {
            ConsoleExt.WriteLine($"No new hosts found", ConsoleColor.Blue);
        }

        Console.WriteLine();

        if (removedHosts.Count > 0)
        {
            // Better term for removed host?
            Console.WriteLine($"Previously active hosts:");

            removedHostsTable.ToArray().To2D().PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {"previously active host".ToQuantity(removedHosts.Count)}", ConsoleColor.Red);
        }
        else
        {
            ConsoleExt.WriteLine($"No previously active hosts are currently inactive", ConsoleColor.Blue);
        }
    }
}