# Architecture

ConstructTrack uses a single ASP.NET Core web application that serves both the REST API and the static frontend. MongoDB is used as the application database. Docker Compose starts both services for a repeatable local deployment.

## Runtime Components

```text
Browser
  │
  │ HTML/CSS/JavaScript
  ▼
ASP.NET Core Web App
  │
  ├── Static frontend from wwwroot
  ├── Minimal REST API endpoints
  ├── Project, Asset, Issue services
  └── MongoDB.Driver data access
       │
       ▼
MongoDB Database
```

## Backend Layers

| Layer | Responsibility |
|---|---|
| Program.cs | App startup, dependency injection, middleware, API routes |
| Data | MongoDB settings, database context, seed data, indexes |
| Models | Project, Asset, Issue, IssueNote, dashboard response models |
| Dtos | API request contracts |
| Services | Business logic, validation, data access coordination |
| wwwroot | Dashboard interface and browser-side API integration |

## Data Model

### Project

Represents a construction or infrastructure project. It stores project name, client, location, sector, stage, description, progress, start date, and target completion.

### Asset

Represents a BIM-linked construction asset or component. It stores a BIM reference, category, location, responsible team, risk level, and status.

### Issue

Represents a site issue, coordination problem, defect, compliance item, or construction risk. It can be linked to an asset and stores priority, status, assigned owner, due date, tags, attachments, and notes.

## Design Decisions

- A document database is suitable because construction issues, notes, tags, and asset metadata can vary between projects.
- The API keeps project, asset, and issue workflows separate but connected through project and asset IDs.
- The frontend is intentionally dependency-free so the project can run without a separate JavaScript build step.
- Docker Compose makes the application easier to review because the database and web app start together.
- Seed data gives an immediate realistic demo without manual setup.
