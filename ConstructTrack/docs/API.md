# API Reference

Base URL for local Docker deployment:

```text
http://localhost:8080
```

## Health

### `GET /health`

Returns service status.

Response example:

```json
{
  "status": "healthy",
  "service": "ConstructTrack",
  "timestamp": "2026-05-23T09:00:00Z"
}
```

## Dashboard

### `GET /api/dashboard`

Returns totals, risk indicators, breakdowns, and recent issue activity.

## Projects

### `GET /api/projects`

Returns all projects sorted by name.

### `GET /api/projects/{id}`

Returns one project by ID.

### `POST /api/projects`

Creates a new project.

Request body:

```json
{
  "code": "CBD-TOWER-01",
  "name": "CBD Tower Fitout",
  "client": "Example Construction Group",
  "location": "Melbourne CBD, VIC",
  "sector": "Commercial Construction",
  "stage": "Construction",
  "description": "Fitout coordination dashboard for site issues and asset tracking.",
  "progress": 30,
  "startDate": "2026-05-01T00:00:00Z",
  "targetCompletion": "2026-09-30T00:00:00Z"
}
```

## Assets

### `GET /api/projects/{projectId}/assets`

Returns BIM-linked assets for a project.

### `POST /api/assets`

Creates a new asset.

Request body:

```json
{
  "projectId": "project-id",
  "bimReference": "BIM-L03-MECH-011",
  "name": "Level 3 Mechanical Riser",
  "category": "Mechanical",
  "location": "Level 3 Core A",
  "responsibleTeam": "Mechanical Services",
  "riskLevel": "High",
  "status": "Under Review"
}
```

Allowed asset risk values:

```text
Low, Medium, High, Critical
```

Allowed asset statuses:

```text
Active, Under Review, Maintenance Required, Closed
```

## Issues

### `GET /api/projects/{projectId}/issues`

Returns project issues. Optional query parameters:

```text
status=Open
priority=High
```

Example:

```text
/api/projects/{projectId}/issues?status=Blocked&priority=Critical
```

### `GET /api/issues/{id}`

Returns one issue by ID.

### `POST /api/issues`

Creates a new issue.

Request body:

```json
{
  "projectId": "project-id",
  "assetId": "asset-id",
  "title": "Service clash near grid B4",
  "description": "Cable tray route conflicts with ductwork clearance and requires coordination review.",
  "location": "Level 2 Grid B4",
  "priority": "High",
  "assignedTo": "Electrical Services",
  "dueDate": "2026-06-05T00:00:00Z",
  "tags": ["BIM", "Coordination"],
  "attachmentNames": ["coordination-snapshot.png"]
}
```

Allowed priorities:

```text
Low, Medium, High, Critical
```

New issues start with this status:

```text
Open
```

### `PUT /api/issues/{id}/status`

Updates an issue status and appends a note.

Request body:

```json
{
  "status": "In Progress",
  "author": "Site Coordinator",
  "note": "Mechanical team has started route review."
}
```

Allowed statuses:

```text
Open, In Progress, Blocked, Resolved, Closed
```

### `PUT /api/issues/{id}/assignment`

Updates the assigned team or person and appends a note.

Request body:

```json
{
  "assignedTo": "Structural Engineering",
  "author": "Project Manager",
  "note": "Reassigned for structural clearance confirmation."
}
```

### `DELETE /api/issues/{id}`

Deletes an issue.
