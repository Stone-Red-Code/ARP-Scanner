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
        string monitorTarget = string.IsNullOrWhiteSpace(options.IpRange) && options.AutoDiscover
            ? "all local subnets"
            : options.IpRange ?? "<none>";

        ConsoleExt.WriteLine($"Monitoring IP range '{monitorTarget}' every {options.Delay} seconds...", ConsoleColor.DarkYellow);

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
        IEnumerable<IPAddress> ipAddresses;

        if (options.AutoDiscover && string.IsNullOrWhiteSpace(options.IpRange))
        {
            ipAddresses = GetLocalSubnets();

            if (!ipAddresses.Any())
            {
                ConsoleExt.WriteLine("No local IPv4 subnets found for auto discovery.", ConsoleColor.Red);
                return 2;
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(options.IpRange))
            {
                ConsoleExt.WriteLine("IP range is required when auto discovery is disabled.", ConsoleColor.Red);
                return 2;
            }

            if (!IPAddressRange.TryParse(options.IpRange, out IPAddressRange ipAddressRange))
            {
                ConsoleExt.WriteLine("Invalid IP range!", ConsoleColor.Red);
                return 2;
            }

            ipAddresses = ipAddressRange;
        }

        await macVendorLookup.Initialize(options.Silent);

        long ipAddressesCount = ipAddresses is IPAddressRange range
            ? range.Count()
            : ipAddresses.LongCount();
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

        bool suppressPerIpOutput = options is MonitorOptions monitorOptions && (monitorOptions.ChangesOnly || monitorOptions.Summary);

        await Parallel.ForEachAsync(ipAddresses, parallelOptions, async (IPAddress ipAddress, CancellationToken _) =>
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
                if (!options.Silent && !suppressPerIpOutput)
                {
                    ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] |   Active: {ipAddress}", ConsoleColor.Green);
                }
                activeHosts.Add([.. info]);
            }
            else if (fail)
            {
                if (!options.Silent && !suppressPerIpOutput)
                {
                    ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] |   Failed: {ipAddress}", ConsoleColor.Red);
                }
            }
            else
            {
                if (!options.Silent && !suppressPerIpOutput)
                {
                    ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] | Inactive: {ipAddress}", ConsoleColor.Red);
                }
            }
        });

        if (previouslyActiveHosts.Count > 0 && !options.Silent)
        {
            PrintDifference(activeHosts, header, options);
        }
        else if (!options.Silent)
        {
            PrintActiveHosts(activeHosts, header, options);
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
                if (!string.IsNullOrWhiteSpace(Path.GetDirectoryName(jsonPath)))
                {
                    _ = Directory.CreateDirectory(Path.GetDirectoryName(jsonPath)!);
                }

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
                if (!string.IsNullOrWhiteSpace(Path.GetDirectoryName(csvPath)))
                {
                    _ = Directory.CreateDirectory(Path.GetDirectoryName(csvPath)!);
                }

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

    private static void PrintActiveHosts(ConcurrentBag<string[]> activeHosts, List<string> header, ScanOptions options)
    {
        IEnumerable<string[]> filtered = FilterByVendorAndMacPrefix(activeHosts, options);

        List<string[]> activeHostsTable = [.. filtered];
        activeHostsTable.Insert(0, [.. header]);

        Console.WriteLine();

        int filteredCount = GetHostCount(activeHostsTable);

        if (filteredCount > 0)
        {
            PrintSection("Active hosts", "active host", activeHostsTable, options, ConsoleColor.Green);
        }
        else
        {
            ConsoleExt.WriteLine("No active hosts found", ConsoleColor.Red);
        }
    }

    private static void PrintDifference(ConcurrentBag<string[]> activeHosts, List<string> header, ScanOptions options)
    {
        List<string[]> newHosts = activeHosts.Where(activeHost => !previouslyActiveHosts.Exists(previousHost => previousHost[1] == activeHost[1])).ToList();
        List<string[]> removedHosts = previouslyActiveHosts.Where(previousHost => !activeHosts.Any(activeHost => activeHost[1] == previousHost[1])).ToList();

        List<string[]> newHostsTable = [.. FilterByVendorAndMacPrefix(newHosts, options)];
        newHostsTable.Insert(0, [.. header]);

        List<string[]> removedHostsTable = [.. FilterByVendorAndMacPrefix(removedHosts, options)];
        removedHostsTable.Insert(0, [.. header]);

        Console.WriteLine();

        bool isMonitoring = options is MonitorOptions;

        int newCount = GetHostCount(newHostsTable);

        if (newCount > 0)
        {
            PrintSection("New hosts", "active host", newHostsTable, options, ConsoleColor.Green, " (summary mode)");
        }
        else
        {
            ConsoleExt.WriteLine("No new hosts found", ConsoleColor.Blue);
        }

        Console.WriteLine();

        int removedCount = GetHostCount(removedHostsTable);

        if (removedCount > 0)
        {
            // Better term for removed host?
            PrintSection("Previously active hosts", "previously active host", removedHostsTable, options, ConsoleColor.Red, " now inactive (summary mode)");
        }
        else
        {
            ConsoleExt.WriteLine("No previously active hosts are currently inactive", ConsoleColor.Blue);
        }

        if (isMonitoring && options is MonitorOptions monitorOptions)
        {
            // Execute user-defined commands for new and removed hosts, if configured.
            JsonResult jsonResult = JsonResult.Parse([.. activeHosts], previouslyActiveHosts);

            if (newHosts.Count > 0 && !string.IsNullOrWhiteSpace(monitorOptions.OnNewCommand))
            {
                ExecuteMonitorCommand(monitorOptions.OnNewCommand!, jsonResult.NewHosts);
            }

            if (removedHosts.Count > 0 && !string.IsNullOrWhiteSpace(monitorOptions.OnRemovedCommand))
            {
                ExecuteMonitorCommand(monitorOptions.OnRemovedCommand!, jsonResult.RemovedHosts);
            }
        }
    }

    private static IEnumerable<string[]> FilterByVendorAndMacPrefix(IEnumerable<string[]> hosts, ScanOptions options)
    {
        IEnumerable<string[]> filtered = hosts;

        if (!string.IsNullOrWhiteSpace(options.VendorFilter))
        {
            string vendorFilter = options.VendorFilter.Trim();
            filtered = filtered.Where(h => h.Length > 2 && h[2].Contains(vendorFilter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(options.MacPrefixFilter))
        {
            string macPrefix = options.MacPrefixFilter.Trim().Replace("-", ":").ToUpperInvariant();
            filtered = filtered.Where(h => h.Length > 1 && h[1].Replace("-", ":").ToUpperInvariant().StartsWith(macPrefix, StringComparison.Ordinal));
        }

        return filtered;
    }

    private static int GetHostCount(List<string[]> tableWithHeader)
    {
        // subtract one for header row
        return Math.Max(0, tableWithHeader.Count - 1);
    }

    private static void PrintSection(string title, string itemLabel, List<string[]> tableWithHeader, ScanOptions options, ConsoleColor color, string? summarySuffix = null)
    {
        int count = GetHostCount(tableWithHeader);
        if (count <= 0)
        {
            return;
        }

        if (IsSummaryMode(options))
        {
            string suffix = summarySuffix ?? " (summary mode)";
            ConsoleExt.WriteLine($"{title} {itemLabel.ToQuantity(count)}{suffix}", color);
        }
        else
        {
            Console.WriteLine(title + ":");
            tableWithHeader.ToArray().To2D().PrintTable(TableStyle.List);
            ConsoleExt.WriteLine($"{Environment.NewLine}Found {itemLabel.ToQuantity(count)}", color);
        }
    }

    private static bool IsSummaryMode(ScanOptions options)
    {
        return options is MonitorOptions monitorOptions && monitorOptions.Summary;
    }

    private static List<IPAddress> GetLocalSubnets()
    {
        List<IPAddress> addresses = [];

        foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
            foreach (UnicastIPAddressInformation unicast in ipProperties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    continue;
                }

                int prefixLength = unicast.PrefixLength;
                if (prefixLength is <= 0 or > 32)
                {
                    continue;
                }

                uint mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);
                byte[] ipBytes = unicast.Address.GetAddressBytes();
                uint ip = (uint)((ipBytes[0] << 24) | (ipBytes[1] << 16) | (ipBytes[2] << 8) | ipBytes[3]);
                uint network = ip & mask;
                uint broadcast = network | ~mask;

                for (uint addr = network + 1; addr < broadcast; addr++)
                {
                    byte[] addrBytes =
                    [
                        (byte)((addr >> 24) & 0xFF),
                        (byte)((addr >> 16) & 0xFF),
                        (byte)((addr >> 8) & 0xFF),
                        (byte)(addr & 0xFF)
                    ];
                    addresses.Add(new IPAddress(addrBytes));
                }
            }
        }

        return addresses;
    }

    private static void ExecuteMonitorCommand(string command, IEnumerable<JsonResult.HostInformation> hosts)
    {
        try
        {
            ProcessStartInfo psi = new()
            {
                FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/sh",
                Arguments = OperatingSystem.IsWindows() ? $"/C {command}" : $"-c \"{command}\"",
                RedirectStandardInput = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using Process process = Process.Start(psi)!;
            string json = JsonSerializer.Serialize(hosts, jsonSerializerOptions);
            process.StandardInput.WriteLine(json);
            process.StandardInput.Close();
        }
        catch (Exception ex)
        {
            ConsoleExt.WriteLine($"Failed to execute monitor command '{command}': {ex.Message}", ConsoleColor.Red);
        }
    }
}