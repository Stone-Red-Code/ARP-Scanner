using System.Text.Json.Serialization;

namespace ARP_Scanner;

internal class MacInformation
{
    [JsonPropertyName("macPrefix")]
    public required string MacPrefix { get; set; }

    [JsonPropertyName("vendorName")]
    public required string VendorName { get; set; }

    [JsonPropertyName("private")]
    public bool? Private { get; set; }

    [JsonPropertyName("blockType")]
    public required string BlockType { get; set; }

    [JsonPropertyName("lastUpdate")]
    public required string LastUpdate { get; set; }
}