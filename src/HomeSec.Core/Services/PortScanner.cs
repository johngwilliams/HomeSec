using System.Net;
using System.Net.Sockets;
using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Performs TCP connect scanning on discovered devices to identify open ports/services.
/// </summary>
public sealed class PortScanner
{
    private const int ConnectTimeoutMs = 600;
    private const int BannerTimeoutMs = 400;
    private const int MaxConcurrentPerDevice = 30;
    private const int MaxConcurrentDevices = 4;

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

    /// <summary>
    /// Scan all devices in parallel (up to MaxConcurrentDevices at a time).
    /// </summary>
    public async Task ScanAllDevicesAsync(
        IList<NetworkDevice> devices,
        Action<int>? onDeviceComplete = null,
        CancellationToken cancellationToken = default)
    {
        var semaphore = new SemaphoreSlim(MaxConcurrentDevices);
        int completed = 0;

        var tasks = devices.Select(async device =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                await ScanDeviceAsync(device, cancellationToken);
                int done = Interlocked.Increment(ref completed);
                onDeviceComplete?.Invoke(done);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
    }

    public async Task ScanDeviceAsync(
        NetworkDevice device,
        CancellationToken cancellationToken = default)
    {
        StatusUpdate?.Invoke($"Port scanning {device.IpAddress}...");

        var semaphore = new SemaphoreSlim(MaxConcurrentPerDevice);
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

    private static async Task<PortInfo?> CheckPortAsync(IPAddress ip, int port)
    {
        try
        {
            using var client = new TcpClient { LingerState = new LingerOption(true, 0) };
            using var connectCts = new CancellationTokenSource(ConnectTimeoutMs);

            await client.ConnectAsync(ip, port, connectCts.Token);

            string? banner = null;
            try
            {
                var stream = client.GetStream();
                using var bannerCts = new CancellationTokenSource(BannerTimeoutMs);
                var buffer = new byte[256];
                int read = await stream.ReadAsync(buffer.AsMemory(0, 256), bannerCts.Token);
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
