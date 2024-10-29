namespace ARP_Scanner;

internal class JsonResult
{
    public IEnumerable<HostInformation> Hosts { get; set; } = [];

    public IEnumerable<HostInformation> NewHosts { get; set; } = [];

    public IEnumerable<HostInformation> RemovedHosts { get; set; } = [];

    public static JsonResult Parse(IEnumerable<string[]> activeHosts, List<string[]> previousHosts)
    {
        JsonResult result = new JsonResult
        {
            Hosts = activeHosts.Select(HostInformation.Parse)
        };

        if (previousHosts.Count == 0)
        {
            return result;
        }

        result.NewHosts = result.Hosts.Where(host => !previousHosts.Exists(previousHost => previousHost[1] == host.Mac));
        result.RemovedHosts = previousHosts.Where(previousHost => !result.Hosts.Any(host => host.Mac == previousHost[1])).Select(HostInformation.Parse);

        return result;
    }

    public class HostInformation
    {
        public required string Ip { get; set; }
        public required string Mac { get; set; }
        public required string VendorName { get; set; }
        public required string BlockType { get; set; }
        public bool? Private { get; set; }
        public required string LastUpdate { get; set; }

        public static HostInformation Parse(string[] row)
        {
            bool success = bool.TryParse(row[4], out bool isPrivate);

            return new HostInformation
            {
                Ip = row[0],
                Mac = row[1],
                VendorName = row[2],
                BlockType = row[3],
                Private = success ? isPrivate : null,
                LastUpdate = row[5]
            };
        }
    }
}