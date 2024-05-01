using ArpLookup;

using CuteUtils.Misc;

using NetTools;

using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace ARP_Scanner;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        MacVendorLookup macVendorLookup = new MacVendorLookup();

        if (!Arp.IsSupported)
        {
            ConsoleExt.WriteLine("ARP is not supported on this platform!", ConsoleColor.Red);
            return;
        }

        if (!IPAddressRange.TryParse(string.Join("", args), out IPAddressRange ipAddressRange))
        {
            ConsoleExt.WriteLine("Invalid IP range!", ConsoleColor.Red);
            return;
        }

        await macVendorLookup.Initialize();

        long ipAddressesCount = ipAddressRange.Count();
        long processedIpAddressesCount = 0;
        int numberOfDigits = ipAddressesCount.ToString().Length;

        List<string> header = ["IP", "MAC"];
        ConcurrentBag<string[]> activeHosts = [];

        header.AddRange([nameof(MacInformation.VendorName), nameof(MacInformation.BlockType), nameof(MacInformation.Private), nameof(MacInformation.LastUpdate)]);

        ConsoleExt.WriteLine("Starting scan...", ConsoleColor.DarkYellow);

        await Parallel.ForEachAsync(ipAddressRange, async (IPAddress ipAddress, CancellationToken _) =>
        {
            PhysicalAddress? mac = null;
            bool fail = false;

            try
            {
                mac = await Arp.LookupAsync(ipAddress);
            }
            catch (Exception ex)
            {
                ConsoleExt.WriteLine($"Failed to lookup MAC address for {ipAddress}: {ex.Message}", ConsoleColor.Red);
                fail = true;
            }

            long localProcessedIpAddressesCount = Interlocked.Increment(ref processedIpAddressesCount);
            if (mac is not null && Array.Exists(mac.GetAddressBytes(), b => b != 0))
            {
                string formattedMac = BitConverter.ToString(mac.GetAddressBytes());

                MacInformation macInformation = macVendorLookup.GetInformation(formattedMac);

                List<string> info = [ipAddress.ToString(), formattedMac, macInformation.VendorName, macInformation.BlockType, macInformation.Private.ToString() ?? "Unknown", macInformation.LastUpdate];
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] |   Active: {ipAddress}", ConsoleColor.Green);
                activeHosts.Add([.. info]);
            }
            else if (fail)
            {
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] |   Failed: {ipAddress}", ConsoleColor.Red);
            }
            else
            {
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] | Inactive: {ipAddress}", ConsoleColor.Red);
            }
        });

        if (!activeHosts.IsEmpty)
        {
            Console.WriteLine(Environment.NewLine + $"Active host{(activeHosts.Count == 1 ? "s" : "")}:");

            List<string[]>? activeHostsTable = [.. activeHosts];

            activeHostsTable.Insert(0, [.. header]);

            activeHostsTable.ToArray().To2D().PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {activeHosts.Count} active host{(activeHosts.Count == 1 ? "s" : "")}", ConsoleColor.Green);
        }
        else
        {
            ConsoleExt.WriteLine($"{Environment.NewLine}No active hosts found", ConsoleColor.Red);
        }
    }
}