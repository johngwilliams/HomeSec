using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace HomeSec.Core.Services;

/// <summary>
/// Auto-detects the local network subnet and gateway.
/// </summary>
public sealed class SubnetDetector
{
    public (IPAddress Gateway, string SubnetCidr, IPAddress LocalIp) Detect()
    {
        var bestInterface = GetBestNetworkInterface();
        if (bestInterface is null)
            throw new InvalidOperationException(
                "No active network interface found. Please check your network connection.");

        var ipProps = bestInterface.GetIPProperties();
        var unicast = ipProps.UnicastAddresses
            .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

        if (unicast is null)
            throw new InvalidOperationException(
                "No IPv4 address found on the active network interface.");

        var localIp = unicast.Address;
        var mask = unicast.IPv4Mask;
        var gateway = ipProps.GatewayAddresses
            .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address
            ?? localIp;

        var networkAddress = GetNetworkAddress(localIp, mask);
        int prefixLength = GetPrefixLength(mask);
        string cidr = $"{networkAddress}/{prefixLength}";

        return (gateway, cidr, localIp);
    }

    /// <summary>
    /// Enumerates all host IPs in the detected subnet (excluding network and broadcast).
    /// </summary>
    public IEnumerable<IPAddress> GetSubnetHosts(string cidr)
    {
        var parts = cidr.Split('/');
        var networkIp = IPAddress.Parse(parts[0]);
        int prefix = int.Parse(parts[1]);
        int hostBits = 32 - prefix;
        uint hostCount = (1u << hostBits) - 2; // exclude network & broadcast

        var networkBytes = networkIp.GetAddressBytes();
        uint networkUint = (uint)(networkBytes[0] << 24 | networkBytes[1] << 16 |
                                   networkBytes[2] << 8 | networkBytes[3]);

        for (uint i = 1; i <= hostCount; i++)
        {
            uint hostUint = networkUint + i;
            yield return new IPAddress(new[]
            {
                (byte)(hostUint >> 24),
                (byte)(hostUint >> 16),
                (byte)(hostUint >> 8),
                (byte)hostUint
            });
        }
    }

    private static NetworkInterface? GetBestNetworkInterface()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                         && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback
                         && ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .OrderByDescending(ni => ni.Speed)
            .ThenByDescending(ni => ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 1 : 0)
            .FirstOrDefault();
    }

    private static IPAddress GetNetworkAddress(IPAddress address, IPAddress mask)
    {
        var addrBytes = address.GetAddressBytes();
        var maskBytes = mask.GetAddressBytes();
        var result = new byte[4];
        for (int i = 0; i < 4; i++)
            result[i] = (byte)(addrBytes[i] & maskBytes[i]);
        return new IPAddress(result);
    }

    private static int GetPrefixLength(IPAddress mask)
    {
        var bytes = mask.GetAddressBytes();
        int length = 0;
        foreach (byte b in bytes)
        {
            for (int i = 7; i >= 0; i--)
            {
                if ((b & (1 << i)) != 0) length++;
                else return length;
            }
        }
        return length;
    }
}
