using ConstructTrack.Web.Data;
using ConstructTrack.Web.Dtos;
using ConstructTrack.Web.Services;
using MongoDB.Driver;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<MongoSettings>(builder.Configuration.GetSection("Mongo"));
builder.Services.AddSingleton<MongoContext>();
builder.Services.AddSingleton<SeedData>();
builder.Services.AddScoped<ProjectService>();
builder.Services.AddScoped<AssetService>();
builder.Services.AddScoped<IssueService>();
builder.Services.AddScoped<DashboardService>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("LocalDevelopment", policy =>
    {
        policy.AllowAnyHeader()
            .AllowAnyMethod()
            .AllowAnyOrigin();
    });
});

var app = builder.Build();

app.UseCors("LocalDevelopment");
app.UseDefaultFiles();
app.UseStaticFiles();

using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<MongoContext>();
    var seedData = scope.ServiceProvider.GetRequiredService<SeedData>();
    await context.EnsureIndexesAsync();
    await seedData.RunAsync();
}

app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    service = "ConstructTrack",
    timestamp = DateTime.UtcNow
}));

app.MapGet("/api/dashboard", async (DashboardService service, CancellationToken cancellationToken) =>
{
    var stats = await service.GetStatsAsync(cancellationToken);
    return Results.Ok(stats);
});

app.MapGet("/api/projects", async (ProjectService service, CancellationToken cancellationToken) =>
{
    var projects = await service.GetAllAsync(cancellationToken);
    return Results.Ok(projects);
});

app.MapGet("/api/projects/{id}", async (string id, ProjectService service, CancellationToken cancellationToken) =>
{
    var project = await service.GetByIdAsync(id, cancellationToken);
    return project is null ? Results.NotFound(new { message = "Project not found." }) : Results.Ok(project);
});

app.MapPost("/api/projects", async (ProjectCreateRequest request, ProjectService service, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Code) || string.IsNullOrWhiteSpace(request.Name))
    {
        return Results.BadRequest(new { message = "Project code and name are required." });
    }

    try
    {
        var project = await service.CreateAsync(request, cancellationToken);
        return Results.Created($"/api/projects/{project.Id}", project);
    }
    catch (MongoWriteException exception) when (exception.WriteError.Category == ServerErrorCategory.DuplicateKey)
    {
        return Results.Conflict(new { message = "A project with this code already exists." });
    }
});

app.MapGet("/api/projects/{projectId}/assets", async (string projectId, AssetService service, CancellationToken cancellationToken) =>
{
    var assets = await service.GetByProjectAsync(projectId, cancellationToken);
    return Results.Ok(assets);
});

app.MapPost("/api/assets", async (AssetCreateRequest request, AssetService assetService, ProjectService projectService, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.ProjectId) || string.IsNullOrWhiteSpace(request.Name))
    {
        return Results.BadRequest(new { message = "Project ID and asset name are required." });
    }

    var project = await projectService.GetByIdAsync(request.ProjectId, cancellationToken);
    if (project is null)
    {
        return Results.NotFound(new { message = "Project not found." });
    }

    var asset = await assetService.CreateAsync(request, cancellationToken);
    return Results.Created($"/api/assets/{asset.Id}", asset);
});

app.MapGet("/api/projects/{projectId}/issues", async (
    string projectId,
    string? status,
    string? priority,
    IssueService service,
    CancellationToken cancellationToken) =>
{
    var issues = await service.GetByProjectAsync(projectId, status, priority, cancellationToken);
    return Results.Ok(issues);
});

app.MapGet("/api/issues/{id}", async (string id, IssueService service, CancellationToken cancellationToken) =>
{
    var issue = await service.GetByIdAsync(id, cancellationToken);
    return issue is null ? Results.NotFound(new { message = "Issue not found." }) : Results.Ok(issue);
});

app.MapPost("/api/issues", async (
    IssueCreateRequest request,
    IssueService issueService,
    ProjectService projectService,
    AssetService assetService,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.ProjectId) || string.IsNullOrWhiteSpace(request.Title))
    {
        return Results.BadRequest(new { message = "Project ID and issue title are required." });
    }

    var project = await projectService.GetByIdAsync(request.ProjectId, cancellationToken);
    if (project is null)
    {
        return Results.NotFound(new { message = "Project not found." });
    }

    if (!string.IsNullOrWhiteSpace(request.AssetId))
    {
        var asset = await assetService.GetByIdAsync(request.AssetId, cancellationToken);
        if (asset is null || asset.ProjectId != request.ProjectId)
        {
            return Results.BadRequest(new { message = "Asset does not belong to the selected project." });
        }
    }

    var issue = await issueService.CreateAsync(request, cancellationToken);
    return Results.Created($"/api/issues/{issue.Id}", issue);
});

app.MapPut("/api/issues/{id}/status", async (
    string id,
    IssueStatusUpdateRequest request,
    IssueService service,
    CancellationToken cancellationToken) =>
{
    var issue = await service.UpdateStatusAsync(id, request, cancellationToken);
    return issue is null ? Results.NotFound(new { message = "Issue not found." }) : Results.Ok(issue);
});

app.MapPut("/api/issues/{id}/assignment", async (
    string id,
    IssueAssignmentUpdateRequest request,
    IssueService service,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.AssignedTo))
    {
        return Results.BadRequest(new { message = "Assigned person or team is required." });
    }

    var issue = await service.UpdateAssignmentAsync(id, request, cancellationToken);
    return issue is null ? Results.NotFound(new { message = "Issue not found." }) : Results.Ok(issue);
});

app.MapDelete("/api/issues/{id}", async (string id, IssueService service, CancellationToken cancellationToken) =>
{
    var deleted = await service.DeleteAsync(id, cancellationToken);
    return deleted ? Results.NoContent() : Results.NotFound(new { message = "Issue not found." });
});

app.MapFallbackToFile("index.html");

app.Run();
