using ConstructTrack.Web.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace ConstructTrack.Web.Data;

public sealed class MongoContext
{
    private readonly IMongoDatabase _database;

    public MongoContext(IOptions<MongoSettings> options)
    {
        var settings = options.Value;
        var client = new MongoClient(settings.ConnectionString);
        _database = client.GetDatabase(settings.DatabaseName);
    }

    public IMongoCollection<Project> Projects => _database.GetCollection<Project>("projects");
    public IMongoCollection<Asset> Assets => _database.GetCollection<Asset>("assets");
    public IMongoCollection<Issue> Issues => _database.GetCollection<Issue>("issues");

    public async Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        await Projects.Indexes.CreateOneAsync(
            new CreateIndexModel<Project>(
                Builders<Project>.IndexKeys.Ascending(project => project.Code),
                new CreateIndexOptions { Unique = true }),
            cancellationToken: cancellationToken);

        await Assets.Indexes.CreateManyAsync(
            new[]
            {
                new CreateIndexModel<Asset>(Builders<Asset>.IndexKeys.Ascending(asset => asset.ProjectId)),
                new CreateIndexModel<Asset>(Builders<Asset>.IndexKeys.Ascending(asset => asset.BimReference))
            },
            cancellationToken: cancellationToken);

        await Issues.Indexes.CreateManyAsync(
            new[]
            {
                new CreateIndexModel<Issue>(Builders<Issue>.IndexKeys.Ascending(issue => issue.ProjectId)),
                new CreateIndexModel<Issue>(Builders<Issue>.IndexKeys.Ascending(issue => issue.AssetId)),
                new CreateIndexModel<Issue>(Builders<Issue>.IndexKeys.Ascending(issue => issue.Status)),
                new CreateIndexModel<Issue>(Builders<Issue>.IndexKeys.Ascending(issue => issue.Priority)),
                new CreateIndexModel<Issue>(Builders<Issue>.IndexKeys.Descending(issue => issue.UpdatedAt))
            },
            cancellationToken: cancellationToken);
    }
}
