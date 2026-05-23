using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace ConstructTrack.Web.Models;

public sealed class Issue
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();

    [BsonRepresentation(BsonType.ObjectId)]
    public string ProjectId { get; set; } = string.Empty;

    [BsonRepresentation(BsonType.ObjectId)]
    public string? AssetId { get; set; }

    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Priority { get; set; } = "Medium";
    public string Status { get; set; } = "Open";
    public string AssignedTo { get; set; } = string.Empty;
    public DateTime? DueDate { get; set; }
    public List<string> Tags { get; set; } = [];
    public List<string> AttachmentNames { get; set; } = [];
    public List<IssueNote> Notes { get; set; } = [];
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
