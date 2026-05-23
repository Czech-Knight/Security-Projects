namespace ConstructTrack.Web.Dtos;

public sealed record ProjectCreateRequest(
    string Code,
    string Name,
    string Client,
    string Location,
    string Sector,
    string Stage,
    string Description,
    int Progress,
    DateTime StartDate,
    DateTime TargetCompletion);

public sealed record AssetCreateRequest(
    string ProjectId,
    string BimReference,
    string Name,
    string Category,
    string Location,
    string ResponsibleTeam,
    string RiskLevel,
    string Status);

public sealed record IssueCreateRequest(
    string ProjectId,
    string? AssetId,
    string Title,
    string Description,
    string Location,
    string Priority,
    string AssignedTo,
    DateTime? DueDate,
    List<string>? Tags,
    List<string>? AttachmentNames);

public sealed record IssueStatusUpdateRequest(
    string Status,
    string? Author,
    string? Note);

public sealed record IssueAssignmentUpdateRequest(
    string AssignedTo,
    string? Author,
    string? Note);
