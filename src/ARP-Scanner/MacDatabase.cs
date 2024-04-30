namespace ARP_Scanner;

internal class MacDatabase
{
    public DateTime LastUpdate { get; set; }
    public List<MacInformation> MacInformations { get; set; } = [];
}