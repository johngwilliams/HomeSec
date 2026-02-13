using System.Net;

namespace HomeSec.Core.Models;

public sealed class NetworkDevice
{
    public required IPAddress IpAddress { get; init; }
    public string? MacAddress { get; set; }
    public string? Hostname { get; set; }
    public string? Vendor { get; set; }
    public DeviceCategory Category { get; set; } = DeviceCategory.Unknown;
    public string? OperatingSystem { get; set; }
    public List<PortInfo> OpenPorts { get; set; } = [];
    public List<SecurityFinding> Findings { get; set; } = [];
    public bool IsGateway { get; set; }
    public DateTime DiscoveredAt { get; init; } = DateTime.Now;

    public string DisplayName =>
        Hostname ?? Vendor ?? IpAddress.ToString();

    public string CategoryName =>
        Category.ToFriendlyName();

    public int HighestSeverity =>
        Findings.Count > 0
            ? (int)Findings.Max(f => f.Severity)
            : -1;
}
