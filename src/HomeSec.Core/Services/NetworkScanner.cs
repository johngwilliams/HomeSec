using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Discovers live hosts on the local subnet using ICMP ping and ARP.
/// </summary>
public sealed class NetworkScanner
{
    private const int PingTimeoutMs = 500;
    private const int DnsTimeoutMs = 1500;
    private const int MaxConcurrentPings = 80;

    public event Action<string>? StatusUpdate;

    public async Task<List<NetworkDevice>> DiscoverDevicesAsync(
        IEnumerable<IPAddress> hosts,
        CancellationToken cancellationToken = default)
    {
        var hostList = hosts.ToList();
        var devices = new ConcurrentBag<NetworkDevice>();
        var semaphore = new SemaphoreSlim(MaxConcurrentPings);

        StatusUpdate?.Invoke($"Scanning {hostList.Count} addresses...");

        // Read the full ARP table once up front instead of per-host
        var arpTable = ReadArpTable();

        int completed = 0;
        var tasks = hostList.Select(async ip =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var device = await ProbeHostAsync(ip, arpTable);
                if (device is not null)
                {
                    devices.Add(device);
                }

                int done = Interlocked.Increment(ref completed);
                if (done % 25 == 0)
                    StatusUpdate?.Invoke($"Probed {done}/{hostList.Count} addresses ({devices.Count} found)...");
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);

        var result = devices.ToList();
        StatusUpdate?.Invoke($"Discovery complete: {result.Count} devices found.");
        return result;
    }

    private static async Task<NetworkDevice?> ProbeHostAsync(
        IPAddress ip, Dictionary<string, string> arpTable)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, PingTimeoutMs);

            if (reply.Status != IPStatus.Success)
                return null;

            // DNS reverse lookup with a hard timeout so it can't hang
            string? hostname = await DnsLookupWithTimeoutAsync(ip);

            // Fast ARP lookup from pre-read table
            arpTable.TryGetValue(ip.ToString(), out string? mac);

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

    private static async Task<string?> DnsLookupWithTimeoutAsync(IPAddress ip)
    {
        try
        {
            using var cts = new CancellationTokenSource(DnsTimeoutMs);
            var task = Dns.GetHostEntryAsync(ip.ToString(), cts.Token);
            var entry = await task;
            // Don't return the IP address string as the hostname
            if (entry.HostName != ip.ToString())
                return entry.HostName;
        }
        catch
        {
            // Timeout or lookup failed — not critical
        }
        return null;
    }

    /// <summary>
    /// Reads the entire ARP table once via "arp -a" and returns
    /// a dictionary of IP → MAC address.
    /// </summary>
    private static Dictionary<string, string> ReadArpTable()
    {
        var table = new Dictionary<string, string>();
        try
        {
            var psi = new ProcessStartInfo("arp", "-a")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc is null) return table;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                // Find a MAC-shaped token (xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
                string? ip = null;
                string? mac = null;
                foreach (var part in parts)
                {
                    if (IPAddress.TryParse(part, out _) && ip is null)
                        ip = part;
                    else if ((part.Count(c => c == '-') == 5 || part.Count(c => c == ':') == 5) && mac is null)
                        mac = part.Trim().ToUpperInvariant();
                }

                if (ip is not null && mac is not null)
                    table[ip] = mac;
            }
        }
        catch
        {
            // ARP read failed — not critical
        }
        return table;
    }
}
