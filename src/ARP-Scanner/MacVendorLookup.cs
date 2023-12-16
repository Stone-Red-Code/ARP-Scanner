using System.Text.RegularExpressions;

namespace ARP_Scanner;

internal class MacVendorLookup
{
    public readonly string[] header;
    private readonly string[][] fields;

    public MacVendorLookup(string csvPath)
    {
        if (!File.Exists(csvPath))
        {
            header = Array.Empty<string>();
            fields = Array.Empty<string[]>();
            return;
        }

        string[] lines = File.ReadAllLines(csvPath);

        header = lines[0].Split(',');
        fields = lines.Skip(1).Select(l => Regex.Split(l, ",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))")).ToArray();
    }

    public string[] GetInformation(string macAdress)
    {
        string[]? data = Array.Find(fields, f => macAdress.StartsWith(f[0]));

        if (fields.Length == 0 || header.Length == 0)
        {
            return Array.Empty<string>();
        }
        else if (data is null)
        {
            string[] result = new string[header.Length - 1];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = "Unknown";
            }
            return result;
        }
        else
        {
            List<string> result = new List<string>();
            for (int i = 1; i < header.Length; i++)
            {
                result.Add($"{data[i]}");
            }
            return result.ToArray();
        }
    }

    public string[] GetHeader()
    {
        return header!.Skip(1).ToArray();
    }
}