using System.Net;

namespace HomeSec.Core.Models;

public sealed class SubnetInfo
{
    public required string InterfaceName { get; init; }
    public required string InterfaceType { get; init; }
    public required IPAddress LocalIp { get; init; }
    public required IPAddress Gateway { get; init; }
    public required IPAddress SubnetMask { get; init; }
    public required string Cidr { get; init; }
    public required int PrefixLength { get; init; }
    public required long SpeedMbps { get; init; }

    public bool IsClassC => PrefixLength >= 24 && PrefixLength <= 24
                            && IsPrivateRange(LocalIp);

    public bool IsClassB => PrefixLength >= 16 && PrefixLength < 24
                            && IsPrivateRange(LocalIp);

    public bool IsClassA => PrefixLength >= 8 && PrefixLength < 16
                            && IsPrivateRange(LocalIp);

    public string DisplayLabel =>
        $"{Cidr}  ({InterfaceName} — {InterfaceType})";

    public string DetailLabel =>
        $"Gateway: {Gateway}  |  Your IP: {LocalIp}  |  {SpeedMbps} Mbps";

    private static bool IsPrivateRange(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        return bytes[0] == 10
               || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
               || (bytes[0] == 192 && bytes[1] == 168);
    }
}
