using System.Net;
using System.Net.NetworkInformation;
using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Discovers live hosts on the local subnet using ICMP ping and ARP.
/// </summary>
public sealed class NetworkScanner
{
    private const int PingTimeoutMs = 1000;
    private const int MaxConcurrentPings = 50;

    public event Action<string>? StatusUpdate;

    public async Task<List<NetworkDevice>> DiscoverDevicesAsync(
        IEnumerable<IPAddress> hosts,
        CancellationToken cancellationToken = default)
    {
        var hostList = hosts.ToList();
        var devices = new List<NetworkDevice>();
        var semaphore = new SemaphoreSlim(MaxConcurrentPings);

        StatusUpdate?.Invoke($"Scanning {hostList.Count} addresses...");

        var tasks = hostList.Select(async ip =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var device = await ProbeHostAsync(ip);
                return device;
            }
            finally
            {
                semaphore.Release();
            }
        });

        var results = await Task.WhenAll(tasks);

        foreach (var device in results)
        {
            if (device is not null)
            {
                devices.Add(device);
            }
        }

        StatusUpdate?.Invoke($"Discovery complete: {devices.Count} devices found.");
        return devices;
    }

    private static async Task<NetworkDevice?> ProbeHostAsync(IPAddress ip)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, PingTimeoutMs);

            if (reply.Status != IPStatus.Success)
                return null;

            string? hostname = null;
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(ip);
                hostname = hostEntry.HostName;
            }
            catch
            {
                // DNS reverse lookup failed — not critical
            }

            string? mac = GetMacFromArpCache(ip);

            return new NetworkDevice
            {
                IpAddress = ip,
                Hostname = hostname,
                MacAddress = mac
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Attempts to read the MAC address from the OS ARP cache via the
    /// .NET NetworkInformation layer. Falls back to null if unavailable.
    /// </summary>
    private static string? GetMacFromArpCache(IPAddress ip)
    {
        // On Windows we can read ARP via "arp -a" or P/Invoke SendARP.
        // Using a simple process call here for portability within Windows.
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("arp", $"-a {ip}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null) return null;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            // Parse the ARP output for a MAC address pattern
            foreach (var line in output.Split('\n'))
            {
                if (!line.Contains(ip.ToString())) continue;
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    if (part.Count(c => c == '-') == 5 || part.Count(c => c == ':') == 5)
                        return part.Trim().ToUpperInvariant();
                }
            }
        }
        catch
        {
            // ARP lookup failed — not critical
        }
        return null;
    }
}
