using ARP_Scanner;

using NetTools;

using Stone_Red_Utilities.CollectionExtentions;
using Stone_Red_Utilities.ConsoleExtentions;

using System.Collections.Concurrent;
using System.Net;

internal class Program
{
    private static void Main(string[] args)
    {
        bool success = false;
        IPAddress[]? ipAddresses = null;
        MacVendorLookup macVendorLookup = new MacVendorLookup("mac-vendors.csv");

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

        Parallel.ForEach(ipAddresses, ipAddress =>
        {
            string? mac = new ArpUtilities().SendArpRequest(ipAddress);

            Interlocked.Increment(ref processedIpAddressesCount);
            if (mac is not null)
            {
                List<string> info = new List<string> { ipAddress.ToString(), mac };
                info.AddRange(macVendorLookup.GetInformation(mac));
                ConsoleExt.WriteLine($"Progress: {processedIpAddressesCount}/{ipAddressesCount} [{100d / ipAddressesCount * processedIpAddressesCount:0.00}%] | Active: {ipAddress}", ConsoleColor.Green);
                activeHosts.Add(info.ToArray());
            }
            else
            {
                ConsoleExt.WriteLine($"Progress: {processedIpAddressesCount}/{ipAddressesCount} [{100d / ipAddressesCount * processedIpAddressesCount:0.00}%] | Inactive: {ipAddress}", ConsoleColor.Red);
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