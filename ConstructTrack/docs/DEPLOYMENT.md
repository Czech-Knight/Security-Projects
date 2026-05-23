# Deployment Guide

## Docker Compose Deployment

From the repository root:

```bash
docker compose up --build
```

Open:

```text
http://localhost:8080
```

Stop services:

```bash
docker compose down
```

Reset the database:

```bash
docker compose down -v
```

## Environment Variables

| Variable | Example | Purpose |
|---|---|---|
| `ASPNETCORE_ENVIRONMENT` | `Production` | Runtime environment |
| `Mongo__ConnectionString` | `mongodb://mongodb:27017` | MongoDB connection string |
| `Mongo__DatabaseName` | `constructtrack` | Database name |

## IIS Deployment Path

1. Install the .NET Hosting Bundle for the target .NET runtime on the Windows Server/IIS machine.
2. Publish the application:

```bash
cd src/ConstructTrack.Web
dotnet publish -c Release -o ./publish
```

3. Create an IIS website pointing to the `publish` folder.
4. Set the application pool to `No Managed Code`.
5. Add environment variables for MongoDB connection settings.
6. Confirm `/health` returns a healthy response.

## AWS Deployment Path

Recommended simple options:

- Deploy the Docker image to Amazon ECS or AWS App Runner.
- Use MongoDB Atlas for managed database hosting.
- Store the MongoDB connection string in a secret manager or protected environment variable.
- Place the service behind HTTPS using the platform load balancer or managed ingress.

## Production Checklist

- Use HTTPS.
- Move MongoDB credentials to secrets or protected environment variables.
- Restrict database network access.
- Add authentication before exposing real client data.
- Enable application logging and monitoring.
- Add backup and restore policy for MongoDB.
- Configure deployment health checks using `/health`.
