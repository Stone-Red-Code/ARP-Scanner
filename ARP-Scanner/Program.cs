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
        bool success = false;
        IPAddress[]? ipAddresses = null;
        MacVendorLookup macVendorLookup = new MacVendorLookup("mac-vendors.csv");

        if (!Arp.IsSupported)
        {
            ConsoleExt.WriteLine("ARP is not supported on this platform!", ConsoleColor.Red);
            return;
        }

        if (args.Length >= 1)
        {
            success = IPAddressRange.TryParse(string.Join("", args), out IPAddressRange iPAddressRange);
            ipAddresses = iPAddressRange.AsEnumerable().ToArray();
        }

        if (!success || ipAddresses is null)
        {
            ConsoleExt.WriteLine("Invalid IP range!", ConsoleColor.Red);
            return;
        }

        int ipAddressesCount = ipAddresses.Length;
        int processedIpAddressesCount = 0;

        List<string> header = new List<string>() { "IP", "MAC" };
        ConcurrentBag<string[]> activeHosts = new ConcurrentBag<string[]>();

        header.AddRange(macVendorLookup.GetHeader());

        ConsoleExt.WriteLine("Starting scan...", ConsoleColor.DarkYellow);

        await Parallel.ForEachAsync(ipAddresses, async (ipAddress, _) =>
        {
            PhysicalAddress? mac = await Arp.LookupAsync(ipAddress);

            int localProcessedIpAddressesCount = Interlocked.Increment(ref processedIpAddressesCount);
            if (mac is not null)
            {
                List<string> info = new List<string> { ipAddress.ToString(), mac.ToString() };
                info.AddRange(macVendorLookup.GetInformation(mac.ToString()));
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount:0.00}%] | Active: {ipAddress}", ConsoleColor.Green);
                activeHosts.Add(info.ToArray());
            }
            else
            {
                ConsoleExt.WriteLine($"Progress: {localProcessedIpAddressesCount}/{ipAddressesCount} [{100d / ipAddressesCount * localProcessedIpAddressesCount:0.00}%] | Inactive: {ipAddress}", ConsoleColor.Red);
            }
        });

        if (!activeHosts.IsEmpty)
        {
            Console.WriteLine(Environment.NewLine + "Active hosts:");

            List<string[]>? activeHostsTable = activeHosts.ToList();

            activeHostsTable.Insert(0, header.ToArray());

            To2D(activeHostsTable.ToArray()).PrintTable(TableStyle.List);

            ConsoleExt.WriteLine($"{Environment.NewLine}Found {activeHosts.Count} active hosts", ConsoleColor.Green);
        }
        else
        {
            ConsoleExt.WriteLine($"{Environment.NewLine}No active hosts found", ConsoleColor.Red);
        }
    }

    private static T[,] To2D<T>(T[][] source)
    {
        try
        {
            int FirstDim = source.Length;
            int SecondDim = source.GroupBy(row => row.Length).Single().Key; // throws InvalidOperationException if source is not rectangular

            T[,]? result = new T[FirstDim, SecondDim];
            for (int i = 0; i < FirstDim; ++i)
            {
                for (int j = 0; j < SecondDim; ++j)
                {
                    result[i, j] = source[i][j];
                }
            }

            return result;
        }
        catch (InvalidOperationException)
        {
            throw new InvalidOperationException("The given jagged array is not rectangular.");
        }
    }
}