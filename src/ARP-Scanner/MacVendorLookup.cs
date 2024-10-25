using CuteUtils.Misc;

using System.Net.Http.Json;
using System.Text.Json;

namespace ARP_Scanner;

internal partial class MacVendorLookup
{
    private const string macLookupUrl = "https://maclookup.app/downloads/json-database/get-db";
    private readonly HttpClient httpClient = new HttpClient() { Timeout = TimeSpan.FromSeconds(20) };

    private MacDatabase macDatabase = new MacDatabase();

    public async Task Initialize(bool silent)
    {
        string cachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "macDatabase.json");

        // Snap support
        string? snapUserCommon = Environment.GetEnvironmentVariable("SNAP_USER_COMMON");

        if (snapUserCommon is not null)
        {
            cachePath = Path.Combine(snapUserCommon, "macDatabase.json");
        }

        if (File.Exists(cachePath))
        {
            try
            {
                macDatabase = JsonSerializer.Deserialize<MacDatabase>(File.ReadAllText(cachePath)) ?? new MacDatabase();
            }
            catch (Exception ex)
            {
                if (!silent)
                {
                    ConsoleExt.WriteLine($"Failed to read MAC database cache: {ex.Message}", ConsoleColor.Red);
                }
            }
        }

        // Update MAC database if it's older than a week
        if (macDatabase.LastUpdate > DateTime.Now.AddDays(-7))
        {
            if (!silent)
            {
                ConsoleExt.WriteLine("Using cached MAC database...", ConsoleColor.DarkYellow);
            }
            return;
        }

        if (!silent)
        {
            ConsoleExt.WriteLine("Downloading MAC database from maclookup.app...", ConsoleColor.DarkYellow);
        }

        List<MacInformation>? newMacInformation = null;

        try
        {
            newMacInformation = await httpClient.GetFromJsonAsync<List<MacInformation>>(macLookupUrl);
        }
        catch (Exception ex)
        {
            if (!silent)
            {
                ConsoleExt.WriteLine($"Failed to download MAC database: {ex.Message}", ConsoleColor.Red);
            }
        }

        if (newMacInformation is null)
        {
            if (silent)
            {
                return;
            }

            if (macDatabase.MacInformations.Count != 0)
            {
                ConsoleExt.WriteLine("Failed to download MAC database, using cache...", ConsoleColor.DarkYellow);
            }
            else
            {
                ConsoleExt.WriteLine("Failed to download MAC database and no cache found, using empty database...", ConsoleColor.Red);
            }
        }
        else
        {
            if (!silent)
            {
                ConsoleExt.WriteLine("MAC database downloaded successfully!", ConsoleColor.Green);
            }

            _ = Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);

            macDatabase.MacInformations = newMacInformation;
            macDatabase.LastUpdate = DateTime.Now;
            File.WriteAllText(cachePath, JsonSerializer.Serialize(macDatabase));
        }
    }

    public MacInformation GetInformation(string macAddress)
    {
        macAddress = macAddress.Replace("-", ":")[..8].ToUpper();

        return macDatabase.MacInformations.Find(m => m.MacPrefix == macAddress) ?? new MacInformation()
        {
            MacPrefix = macAddress,
            VendorName = "Unknown",
            BlockType = "Unknown",
            Private = null,
            LastUpdate = "Unknown"
        };
    }
}