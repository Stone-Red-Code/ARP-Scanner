namespace ARP_Scanner;
internal class JsonResult
{
    public required string Ip { get; set; }
    public required string Mac { get; set; }
    public required string VendorName { get; set; }
    public required string BlockType { get; set; }
    public required bool Private { get; set; }
    public required string LastUpdate { get; set; }

    public static IEnumerable<JsonResult> Parse(List<string[]> activeHosts)
    {
        return activeHosts.Select(row => new JsonResult
        {
            Ip = row[0],
            Mac = row[1],
            VendorName = row[2],
            BlockType = row[3],
            Private = bool.Parse(row[4]),
            LastUpdate = row[5]
        });
    }
}
