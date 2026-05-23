using ConstructTrack.Web.Models;
using MongoDB.Bson;
using MongoDB.Driver;

namespace ConstructTrack.Web.Data;

public sealed class SeedData
{
    private readonly MongoContext _context;

    public SeedData(MongoContext context)
    {
        _context = context;
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        var projectCount = await _context.Projects.CountDocumentsAsync(Builders<Project>.Filter.Empty, cancellationToken: cancellationToken);
        if (projectCount > 0)
        {
            return;
        }

        var project = new Project
        {
            Id = ObjectId.GenerateNewId().ToString(),
            Code = "NME-RAIL-01",
            Name = "North Melbourne Station Access Upgrade",
            Client = "Metro Infrastructure Group",
            Location = "North Melbourne, VIC",
            Sector = "Transport Infrastructure",
            Stage = "Design Coordination",
            Description = "Digital issue tracking for station access works, service coordination, and BIM-linked construction assets.",
            Progress = 42,
            StartDate = DateTime.UtcNow.AddDays(-45),
            TargetCompletion = DateTime.UtcNow.AddDays(120),
            CreatedAt = DateTime.UtcNow.AddDays(-45),
            UpdatedAt = DateTime.UtcNow.AddHours(-8)
        };

        var assets = new List<Asset>
        {
            new()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                ProjectId = project.Id,
                BimReference = "BIM-L02-HVAC-014",
                Name = "Level 2 HVAC Duct Run",
                Category = "Mechanical",
                Location = "Level 2 East Corridor",
                ResponsibleTeam = "Mechanical Services",
                RiskLevel = "High",
                Status = "Under Review",
                CreatedAt = DateTime.UtcNow.AddDays(-20),
                UpdatedAt = DateTime.UtcNow.AddHours(-6)
            },
            new()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                ProjectId = project.Id,
                BimReference = "BIM-GF-STR-006",
                Name = "Ground Floor Transfer Beam",
                Category = "Structural",
                Location = "Ground Floor Grid B4",
                ResponsibleTeam = "Structural Engineering",
                RiskLevel = "Medium",
                Status = "Active",
                CreatedAt = DateTime.UtcNow.AddDays(-18),
                UpdatedAt = DateTime.UtcNow.AddDays(-3)
            },
            new()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                ProjectId = project.Id,
                BimReference = "BIM-L01-ELEC-021",
                Name = "Level 1 Cable Tray Route",
                Category = "Electrical",
                Location = "Level 1 Service Zone",
                ResponsibleTeam = "Electrical Services",
                RiskLevel = "Critical",
                Status = "Maintenance Required",
                CreatedAt = DateTime.UtcNow.AddDays(-15),
                UpdatedAt = DateTime.UtcNow.AddHours(-3)
            }
        };

        var issues = new List<Issue>
        {
            new()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                ProjectId = project.Id,
                AssetId = assets[0].Id,
                Title = "HVAC duct clashes with ceiling support frame",
                Description = "Coordination review identified a clearance conflict between the proposed duct route and ceiling frame. BIM reference requires design review before installation.",
                Location = "Level 2 East Corridor",
                Priority = "High",
                Status = "In Progress",
                AssignedTo = "Mechanical Services",
                DueDate = DateTime.UtcNow.AddDays(5),
                Tags = ["BIM", "Coordination", "Mechanical"],
                AttachmentNames = ["level-2-clash-snapshot.png"],
                Notes =
                [
                    new IssueNote
                    {
                        Author = "Site Coordinator",
                        Message = "Raised from coordination review. Mechanical team to provide revised route.",
                        CreatedAt = DateTime.UtcNow.AddDays(-4)
                    }
                ],
                CreatedAt = DateTime.UtcNow.AddDays(-4),
                UpdatedAt = DateTime.UtcNow.AddHours(-4)
            },
            new()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                ProjectId = project.Id,
                AssetId = assets[2].Id,
                Title = "Electrical tray route requires fire-stopping confirmation",
                Description = "Cable tray penetrations need compliance confirmation before works continue. Documentation is pending from the responsible team.",
                Location = "Level 1 Service Zone",
                Priority = "Critical",
                Status = "Blocked",
                AssignedTo = "Electrical Services",
                DueDate = DateTime.UtcNow.AddDays(-2),
                Tags = ["Electrical", "Compliance", "Inspection"],
                Notes =
                [
                    new IssueNote
                    {
                        Author = "QA Lead",
                        Message = "Marked as blocked until fire-stopping evidence is uploaded.",
                        CreatedAt = DateTime.UtcNow.AddDays(-3)
                    }
                ],
                CreatedAt = DateTime.UtcNow.AddDays(-6),
                UpdatedAt = DateTime.UtcNow.AddHours(-2)
            },
            new()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                ProjectId = project.Id,
                AssetId = assets[1].Id,
                Title = "Transfer beam inspection completed",
                Description = "Structural inspection completed and no further action is required.",
                Location = "Ground Floor Grid B4",
                Priority = "Medium",
                Status = "Resolved",
                AssignedTo = "Structural Engineering",
                DueDate = DateTime.UtcNow.AddDays(1),
                Tags = ["Structural", "Inspection"],
                Notes =
                [
                    new IssueNote
                    {
                        Author = "Structural Engineer",
                        Message = "Inspection notes reviewed and marked resolved.",
                        CreatedAt = DateTime.UtcNow.AddDays(-1)
                    }
                ],
                CreatedAt = DateTime.UtcNow.AddDays(-8),
                UpdatedAt = DateTime.UtcNow.AddDays(-1)
            }
        };

        await _context.Projects.InsertOneAsync(project, cancellationToken: cancellationToken);
        await _context.Assets.InsertManyAsync(assets, cancellationToken: cancellationToken);
        await _context.Issues.InsertManyAsync(issues, cancellationToken: cancellationToken);
    }
}
