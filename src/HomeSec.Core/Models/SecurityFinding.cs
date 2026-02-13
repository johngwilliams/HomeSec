namespace HomeSec.Core.Models;

public sealed class SecurityFinding
{
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required SecuritySeverity Severity { get; init; }
    public required string Recommendation { get; init; }
    public string? AffectedService { get; init; }
    public int? AffectedPort { get; init; }
}
