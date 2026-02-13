using System.Net;
using System.Net.Sockets;
using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Performs TCP connect scanning on discovered devices to identify open ports/services.
/// </summary>
public sealed class PortScanner
{
    private const int ConnectTimeoutMs = 800;
    private const int MaxConcurrentConnections = 30;

    /// <summary>
    /// Common ports to scan on home network devices.
    /// Covers web, file sharing, remote access, IoT, and media services.
    /// </summary>
    private static readonly int[] CommonPorts =
    [
        21,    // FTP
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        80,    // HTTP
        110,   // POP3
        135,   // RPC
        139,   // NetBIOS
        143,   // IMAP
        443,   // HTTPS
        445,   // SMB
        548,   // AFP
        554,   // RTSP (cameras)
        631,   // IPP (printing)
        993,   // IMAPS
        995,   // POP3S
        1433,  // MSSQL
        1883,  // MQTT (IoT)
        1900,  // UPnP/SSDP
        3306,  // MySQL
        3389,  // RDP
        5000,  // UPnP / Synology
        5353,  // mDNS
        5900,  // VNC
        8080,  // HTTP Proxy
        8443,  // HTTPS Alt
        8888,  // HTTP Alt
        9100,  // Raw print
        49152  // UPnP
    ];

    public event Action<string>? StatusUpdate;

    public async Task ScanDeviceAsync(
        NetworkDevice device,
        CancellationToken cancellationToken = default)
    {
        StatusUpdate?.Invoke($"Port scanning {device.IpAddress}...");

        var semaphore = new SemaphoreSlim(MaxConcurrentConnections);
        var tasks = CommonPorts.Select(async port =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                return await CheckPortAsync(device.IpAddress, port);
            }
            finally
            {
                semaphore.Release();
            }
        });

        var results = await Task.WhenAll(tasks);
        device.OpenPorts = results.Where(p => p is not null).Cast<PortInfo>().ToList();
    }

    public async Task ScanAllDevicesAsync(
        IEnumerable<NetworkDevice> devices,
        CancellationToken cancellationToken = default)
    {
        foreach (var device in devices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ScanDeviceAsync(device, cancellationToken);
        }
    }

    private static async Task<PortInfo?> CheckPortAsync(IPAddress ip, int port)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(ConnectTimeoutMs);

            await client.ConnectAsync(ip, port, cts.Token);

            string? banner = null;
            try
            {
                var stream = client.GetStream();
                stream.ReadTimeout = 500;
                var buffer = new byte[256];
                int read = await stream.ReadAsync(buffer.AsMemory(0, 256), cts.Token);
                if (read > 0)
                    banner = System.Text.Encoding.ASCII.GetString(buffer, 0, read).Trim();
            }
            catch
            {
                // Banner grab failed — common for many services
            }

            return new PortInfo
            {
                Port = port,
                IsOpen = true,
                ServiceName = PortInfo.GetCommonServiceName(port),
                Banner = banner
            };
        }
        catch
        {
            return null;
        }
    }
}
