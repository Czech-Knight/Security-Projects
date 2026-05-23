using ConstructTrack.Web.Data;
using ConstructTrack.Web.Dtos;
using ConstructTrack.Web.Models;
using MongoDB.Driver;

namespace ConstructTrack.Web.Services;

public sealed class AssetService
{
    private readonly MongoContext _context;

    public AssetService(MongoContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<Asset>> GetByProjectAsync(string projectId, CancellationToken cancellationToken = default)
    {
        return await _context.Assets
            .Find(asset => asset.ProjectId == projectId)
            .SortBy(asset => asset.Location)
            .ThenBy(asset => asset.Name)
            .ToListAsync(cancellationToken);
    }

    public async Task<Asset?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Assets
            .Find(asset => asset.Id == id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<Asset> CreateAsync(AssetCreateRequest request, CancellationToken cancellationToken = default)
    {
        var asset = new Asset
        {
            ProjectId = request.ProjectId,
            BimReference = request.BimReference.Trim(),
            Name = request.Name.Trim(),
            Category = request.Category.Trim(),
            Location = request.Location.Trim(),
            ResponsibleTeam = request.ResponsibleTeam.Trim(),
            RiskLevel = ValidationRules.NormalizeAssetRisk(request.RiskLevel),
            Status = ValidationRules.NormalizeAssetStatus(request.Status),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _context.Assets.InsertOneAsync(asset, cancellationToken: cancellationToken);
        return asset;
    }
}
