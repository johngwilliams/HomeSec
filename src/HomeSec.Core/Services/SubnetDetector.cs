using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Auto-detects local network subnets across all active interfaces.
/// </summary>
public sealed class SubnetDetector
{
    /// <summary>
    /// Returns all usable IPv4 subnets across every active, non-loopback interface.
    /// Results are sorted so that Class C private networks appear first.
    /// </summary>
    public List<SubnetInfo> DetectAll()
    {
        var subnets = new List<SubnetInfo>();

        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                         && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback
                         && ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

        foreach (var ni in interfaces)
        {
            var ipProps = ni.GetIPProperties();

            foreach (var unicast in ipProps.UnicastAddresses
                         .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork))
            {
                var localIp = unicast.Address;
                var mask = unicast.IPv4Mask;
                var networkAddress = GetNetworkAddress(localIp, mask);
                int prefixLength = GetPrefixLength(mask);

                // Skip link-local (169.254.x.x) and loopback-like addresses
                byte firstOctet = localIp.GetAddressBytes()[0];
                if (firstOctet == 169 || firstOctet == 127)
                    continue;

                var gateway = ipProps.GatewayAddresses
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address
                    ?? localIp;

                subnets.Add(new SubnetInfo
                {
                    InterfaceName = ni.Name,
                    InterfaceType = ni.NetworkInterfaceType.ToString(),
                    LocalIp = localIp,
                    Gateway = gateway,
                    SubnetMask = mask,
                    Cidr = $"{networkAddress}/{prefixLength}",
                    PrefixLength = prefixLength,
                    SpeedMbps = ni.Speed / 1_000_000
                });
            }
        }

        // Sort: Class C private first, then by speed descending
        return subnets
            .OrderByDescending(s => s.IsClassC)
            .ThenByDescending(s => s.SpeedMbps)
            .ToList();
    }

    /// <summary>
    /// Enumerates all host IPs in the given subnet (excluding network and broadcast).
    /// </summary>
    public IEnumerable<IPAddress> GetSubnetHosts(string cidr)
    {
        var parts = cidr.Split('/');
        var networkIp = IPAddress.Parse(parts[0]);
        int prefix = int.Parse(parts[1]);
        int hostBits = 32 - prefix;

        // Guard against absurdly large scans (anything bigger than /16 = 65k hosts)
        if (hostBits > 16)
            hostBits = 16;

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

    internal static IPAddress GetNetworkAddress(IPAddress address, IPAddress mask)
    {
        var addrBytes = address.GetAddressBytes();
        var maskBytes = mask.GetAddressBytes();
        var result = new byte[4];
        for (int i = 0; i < 4; i++)
            result[i] = (byte)(addrBytes[i] & maskBytes[i]);
        return new IPAddress(result);
    }

    internal static int GetPrefixLength(IPAddress mask)
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
