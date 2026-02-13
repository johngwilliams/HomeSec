namespace HomeSec.Core.Models;

public sealed class PortInfo
{
    public int Port { get; init; }
    public string Protocol { get; init; } = "TCP";
    public string ServiceName { get; init; } = "unknown";
    public string? Banner { get; init; }
    public bool IsOpen { get; init; }

    /// <summary>
    /// Well-known port-to-service mapping for common ports.
    /// </summary>
    public static string GetCommonServiceName(int port) => port switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        548 => "AFP",
        554 => "RTSP",
        631 => "IPP (Printing)",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1900 => "UPnP/SSDP",
        3306 => "MySQL",
        3389 => "RDP",
        5000 => "UPnP",
        5353 => "mDNS",
        5900 => "VNC",
        8080 => "HTTP Proxy",
        8443 => "HTTPS Alt",
        8888 => "HTTP Alt",
        9100 => "Print Service",
        49152 => "UPnP",
        _ => $"Port {port}"
    };
}
