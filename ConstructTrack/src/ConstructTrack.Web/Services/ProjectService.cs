using ConstructTrack.Web.Data;
using ConstructTrack.Web.Dtos;
using ConstructTrack.Web.Models;
using MongoDB.Driver;

namespace ConstructTrack.Web.Services;

public sealed class ProjectService
{
    private readonly MongoContext _context;

    public ProjectService(MongoContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<Project>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Projects
            .Find(Builders<Project>.Filter.Empty)
            .SortBy(project => project.Name)
            .ToListAsync(cancellationToken);
    }

    public async Task<Project?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Projects
            .Find(project => project.Id == id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<Project> CreateAsync(ProjectCreateRequest request, CancellationToken cancellationToken = default)
    {
        var project = new Project
        {
            Code = request.Code.Trim().ToUpperInvariant(),
            Name = request.Name.Trim(),
            Client = request.Client.Trim(),
            Location = request.Location.Trim(),
            Sector = request.Sector.Trim(),
            Stage = request.Stage.Trim(),
            Description = request.Description.Trim(),
            Progress = Math.Clamp(request.Progress, 0, 100),
            StartDate = request.StartDate.ToUniversalTime(),
            TargetCompletion = request.TargetCompletion.ToUniversalTime(),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _context.Projects.InsertOneAsync(project, cancellationToken: cancellationToken);
        return project;
    }
}
