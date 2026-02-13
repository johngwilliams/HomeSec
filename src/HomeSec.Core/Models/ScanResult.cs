using System.Net;

namespace HomeSec.Core.Models;

public sealed class ScanResult
{
    public required string SubnetCidr { get; init; }
    public required IPAddress GatewayAddress { get; init; }
    public List<NetworkDevice> Devices { get; init; } = [];
    public DateTime ScanStarted { get; init; } = DateTime.Now;
    public DateTime? ScanCompleted { get; set; }
    public TimeSpan Duration => (ScanCompleted ?? DateTime.Now) - ScanStarted;

    public int TotalDevices => Devices.Count;
    public int CriticalFindings => Devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.Critical));
    public int HighFindings => Devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.High));
    public int MediumFindings => Devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.Medium));
    public int LowFindings => Devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.Low));
    public int TotalFindings => Devices.Sum(d => d.Findings.Count);

    public string OverallRiskLevel
    {
        get
        {
            if (CriticalFindings > 0) return "Critical";
            if (HighFindings > 0) return "High";
            if (MediumFindings > 0) return "Medium";
            if (LowFindings > 0) return "Low";
            return "Good";
        }
    }
}
