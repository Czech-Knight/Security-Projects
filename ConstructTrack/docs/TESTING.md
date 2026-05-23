# Testing and Debugging Notes

## Manual Smoke Test

Start the application:

```bash
docker compose up --build
```

Run the shell smoke test:

```bash
./scripts/smoke-test.sh
```

Or on PowerShell:

```powershell
./scripts/smoke-test.ps1
```

## Browser Test Checklist

- Dashboard loads at `http://localhost:8080`.
- Service status shows online.
- Project name, progress, metadata, and stats load.
- BIM asset cards appear in the asset register.
- Issue table loads seeded issues.
- Status and priority filters work.
- New issue form creates an issue.
- Issue status button updates the workflow.
- Page refresh preserves data because records are stored in MongoDB.

## API Test Checklist

- `GET /health` returns `200 OK`.
- `GET /api/projects` returns seeded project data.
- `GET /api/dashboard` returns totals and issue statistics.
- `GET /api/projects/{projectId}/assets` returns assets.
- `POST /api/issues` creates a new issue.
- `PUT /api/issues/{id}/status` updates status and appends a note.

## Debugging Guide

### Web app does not start

Check container logs:

```bash
docker compose logs web
```

### MongoDB is not ready

Check MongoDB logs:

```bash
docker compose logs mongodb
```

### Reset seed data

```bash
docker compose down -v
docker compose up --build
```

### Port already in use

Change the web port in `docker-compose.yml`:

```yaml
ports:
  - "8081:8080"
```
