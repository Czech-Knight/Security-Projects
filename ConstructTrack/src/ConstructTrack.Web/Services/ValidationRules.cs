namespace ConstructTrack.Web.Services;

public static class ValidationRules
{
    public static readonly HashSet<string> Priorities = new(StringComparer.OrdinalIgnoreCase)
    {
        "Low", "Medium", "High", "Critical"
    };

    public static readonly HashSet<string> IssueStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Open", "In Progress", "Blocked", "Resolved", "Closed"
    };

    public static readonly HashSet<string> AssetRiskLevels = new(StringComparer.OrdinalIgnoreCase)
    {
        "Low", "Medium", "High", "Critical"
    };

    public static readonly HashSet<string> AssetStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Active", "Under Review", "Maintenance Required", "Closed"
    };

    public static string NormalizePriority(string value) => Normalize(value, Priorities, "Medium");
    public static string NormalizeIssueStatus(string value) => Normalize(value, IssueStatuses, "Open");
    public static string NormalizeAssetRisk(string value) => Normalize(value, AssetRiskLevels, "Medium");
    public static string NormalizeAssetStatus(string value) => Normalize(value, AssetStatuses, "Active");

    private static string Normalize(string value, HashSet<string> allowedValues, string defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        var match = allowedValues.FirstOrDefault(allowed => string.Equals(allowed, value.Trim(), StringComparison.OrdinalIgnoreCase));
        return match ?? defaultValue;
    }
}
