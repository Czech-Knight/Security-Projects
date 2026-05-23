using ConstructTrack.Web.Data;
using ConstructTrack.Web.Models;
using MongoDB.Driver;

namespace ConstructTrack.Web.Services;

public sealed class DashboardService
{
    private readonly MongoContext _context;

    public DashboardService(MongoContext context)
    {
        _context = context;
    }

    public async Task<DashboardStats> GetStatsAsync(CancellationToken cancellationToken = default)
    {
        var projects = await _context.Projects.Find(Builders<Project>.Filter.Empty).ToListAsync(cancellationToken);
        var assets = await _context.Assets.Find(Builders<Asset>.Filter.Empty).ToListAsync(cancellationToken);
        var issues = await _context.Issues.Find(Builders<Issue>.Filter.Empty).ToListAsync(cancellationToken);
        var now = DateTime.UtcNow;

        return new DashboardStats
        {
            TotalProjects = projects.Count,
            TotalAssets = assets.Count,
            TotalIssues = issues.Count,
            OpenIssues = issues.Count(issue => issue.Status.Equals("Open", StringComparison.OrdinalIgnoreCase)),
            InProgressIssues = issues.Count(issue => issue.Status.Equals("In Progress", StringComparison.OrdinalIgnoreCase)),
            ResolvedIssues = issues.Count(issue => issue.Status.Equals("Resolved", StringComparison.OrdinalIgnoreCase) || issue.Status.Equals("Closed", StringComparison.OrdinalIgnoreCase)),
            HighPriorityIssues = issues.Count(issue => issue.Priority.Equals("High", StringComparison.OrdinalIgnoreCase) || issue.Priority.Equals("Critical", StringComparison.OrdinalIgnoreCase)),
            OverdueIssues = issues.Count(issue => issue.DueDate.HasValue && issue.DueDate.Value < now && !issue.Status.Equals("Resolved", StringComparison.OrdinalIgnoreCase) && !issue.Status.Equals("Closed", StringComparison.OrdinalIgnoreCase)),
            AverageProjectProgress = projects.Count == 0 ? 0 : Math.Round(projects.Average(project => project.Progress), 1),
            StatusBreakdown = issues
                .GroupBy(issue => issue.Status)
                .Select(group => new BreakdownItem { Name = group.Key, Count = group.Count() })
                .OrderBy(item => item.Name)
                .ToList(),
            PriorityBreakdown = issues
                .GroupBy(issue => issue.Priority)
                .Select(group => new BreakdownItem { Name = group.Key, Count = group.Count() })
                .OrderBy(item => item.Name)
                .ToList(),
            RecentIssues = issues
                .OrderByDescending(issue => issue.UpdatedAt)
                .Take(6)
                .ToList()
        };
    }
}
