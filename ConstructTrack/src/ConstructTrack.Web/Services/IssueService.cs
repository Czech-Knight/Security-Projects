using ConstructTrack.Web.Data;
using ConstructTrack.Web.Dtos;
using ConstructTrack.Web.Models;
using MongoDB.Driver;

namespace ConstructTrack.Web.Services;

public sealed class IssueService
{
    private readonly MongoContext _context;

    public IssueService(MongoContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<Issue>> GetByProjectAsync(
        string projectId,
        string? status = null,
        string? priority = null,
        CancellationToken cancellationToken = default)
    {
        var filters = new List<FilterDefinition<Issue>>
        {
            Builders<Issue>.Filter.Eq(issue => issue.ProjectId, projectId)
        };

        if (!string.IsNullOrWhiteSpace(status))
        {
            filters.Add(Builders<Issue>.Filter.Eq(issue => issue.Status, ValidationRules.NormalizeIssueStatus(status)));
        }

        if (!string.IsNullOrWhiteSpace(priority))
        {
            filters.Add(Builders<Issue>.Filter.Eq(issue => issue.Priority, ValidationRules.NormalizePriority(priority)));
        }

        var filter = Builders<Issue>.Filter.And(filters);
        return await _context.Issues
            .Find(filter)
            .SortByDescending(issue => issue.UpdatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<Issue?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Issues
            .Find(issue => issue.Id == id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<Issue> CreateAsync(IssueCreateRequest request, CancellationToken cancellationToken = default)
    {
        var issue = new Issue
        {
            ProjectId = request.ProjectId,
            AssetId = string.IsNullOrWhiteSpace(request.AssetId) ? null : request.AssetId,
            Title = request.Title.Trim(),
            Description = request.Description.Trim(),
            Location = request.Location.Trim(),
            Priority = ValidationRules.NormalizePriority(request.Priority),
            Status = "Open",
            AssignedTo = request.AssignedTo.Trim(),
            DueDate = request.DueDate?.ToUniversalTime(),
            Tags = CleanList(request.Tags),
            AttachmentNames = CleanList(request.AttachmentNames),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        issue.Notes.Add(new IssueNote
        {
            Author = string.IsNullOrWhiteSpace(request.AssignedTo) ? "System" : request.AssignedTo.Trim(),
            Message = "Issue created and added to the project register.",
            CreatedAt = DateTime.UtcNow
        });

        await _context.Issues.InsertOneAsync(issue, cancellationToken: cancellationToken);
        return issue;
    }

    public async Task<Issue?> UpdateStatusAsync(
        string id,
        IssueStatusUpdateRequest request,
        CancellationToken cancellationToken = default)
    {
        var status = ValidationRules.NormalizeIssueStatus(request.Status);
        var note = BuildNote(request.Author, request.Note, $"Status changed to {status}.");

        var update = Builders<Issue>.Update
            .Set(issue => issue.Status, status)
            .Set(issue => issue.UpdatedAt, DateTime.UtcNow)
            .Push(issue => issue.Notes, note);

        return await _context.Issues
            .FindOneAndUpdateAsync(
                issue => issue.Id == id,
                update,
                new FindOneAndUpdateOptions<Issue> { ReturnDocument = ReturnDocument.After },
                cancellationToken);
    }

    public async Task<Issue?> UpdateAssignmentAsync(
        string id,
        IssueAssignmentUpdateRequest request,
        CancellationToken cancellationToken = default)
    {
        var assignedTo = request.AssignedTo.Trim();
        var note = BuildNote(request.Author, request.Note, $"Assignment changed to {assignedTo}.");

        var update = Builders<Issue>.Update
            .Set(issue => issue.AssignedTo, assignedTo)
            .Set(issue => issue.UpdatedAt, DateTime.UtcNow)
            .Push(issue => issue.Notes, note);

        return await _context.Issues
            .FindOneAndUpdateAsync(
                issue => issue.Id == id,
                update,
                new FindOneAndUpdateOptions<Issue> { ReturnDocument = ReturnDocument.After },
                cancellationToken);
    }

    public async Task<bool> DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        var result = await _context.Issues.DeleteOneAsync(issue => issue.Id == id, cancellationToken);
        return result.DeletedCount == 1;
    }

    private static IssueNote BuildNote(string? author, string? message, string fallbackMessage)
    {
        return new IssueNote
        {
            Author = string.IsNullOrWhiteSpace(author) ? "Project Team" : author.Trim(),
            Message = string.IsNullOrWhiteSpace(message) ? fallbackMessage : message.Trim(),
            CreatedAt = DateTime.UtcNow
        };
    }

    private static List<string> CleanList(IEnumerable<string>? values)
    {
        return values?
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList() ?? [];
    }
}
