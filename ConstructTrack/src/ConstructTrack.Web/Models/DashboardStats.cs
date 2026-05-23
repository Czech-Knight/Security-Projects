namespace ConstructTrack.Web.Models;

public sealed class DashboardStats
{
    public int TotalProjects { get; set; }
    public int TotalAssets { get; set; }
    public int TotalIssues { get; set; }
    public int OpenIssues { get; set; }
    public int InProgressIssues { get; set; }
    public int ResolvedIssues { get; set; }
    public int HighPriorityIssues { get; set; }
    public int OverdueIssues { get; set; }
    public double AverageProjectProgress { get; set; }
    public IReadOnlyList<BreakdownItem> StatusBreakdown { get; set; } = [];
    public IReadOnlyList<BreakdownItem> PriorityBreakdown { get; set; } = [];
    public IReadOnlyList<Issue> RecentIssues { get; set; } = [];
}

public sealed class BreakdownItem
{
    public string Name { get; set; } = string.Empty;
    public int Count { get; set; }
}
