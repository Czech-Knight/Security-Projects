namespace ConstructTrack.Web.Models;

public sealed class IssueNote
{
    public string Author { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
