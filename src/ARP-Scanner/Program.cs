using ArpLookup;

using NetTools;

using Stone_Red_Utilities.CollectionExtentions;
using Stone_Red_Utilities.ConsoleExtentions;

using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace ARP_Scanner;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        MacVendorLookup macVendorLookup = new MacVendorLookup("mac-vendors.csv");

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

        long ipAddressesCount = ipAddressRange.Count();
        long processedIpAddressesCount = 0;
        int numberOfDigits = ipAddressesCount.ToString().Length;

        List<string> header = new List<string>() { "IP", "MAC" };
        ConcurrentBag<string[]> activeHosts = new ConcurrentBag<string[]>();

        header.AddRange(macVendorLookup.GetHeader());

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

                List<string> info = new List<string> { ipAddress.ToString(), formattedMac };
                info.AddRange(macVendorLookup.GetInformation(formattedMac));
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] | Active: {ipAddress}", ConsoleColor.Green);
                activeHosts.Add(info.ToArray());
            }
            else if (fail)
            {
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] | Failed: {ipAddress}", ConsoleColor.Red);
            }
            else
            {
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount.ToString().PadLeft(numberOfDigits)}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount,6:##0.00}%] | Inactive: {ipAddress}", ConsoleColor.Red);
            }
        });

        if (!activeHosts.IsEmpty)
        {
            Console.WriteLine(Environment.NewLine + "Active hosts:");

            List<string[]>? activeHostsTable = activeHosts.ToList();

            activeHostsTable.Insert(0, header.ToArray());

            activeHostsTable.ToArray().To2D().PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {activeHosts.Count} active hosts", ConsoleColor.Green);
        }
        else
        {
            ConsoleExt.WriteLine($"{Environment.NewLine}No active hosts found", ConsoleColor.Red);
        }
    }
}