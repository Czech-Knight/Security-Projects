# ConstructTrack BIM Issue Portal

ConstructTrack is a full-stack web application for managing construction project issues, BIM-linked assets, workflow status, and project progress. It is designed for construction and infrastructure teams that need a clean dashboard for project coordination, defect tracking, asset visibility, and technical reporting.

## Key Features

- Construction project dashboard with progress and risk indicators
- BIM-style asset register using asset references, locations, teams, status, and risk levels
- Issue register for defects, coordination problems, safety risks, and compliance items
- REST API built with ASP.NET Core
- MongoDB document storage for projects, assets, issues, notes, and workflow history
- Static HTML, CSS, and JavaScript frontend served by the .NET application
- Filtering by issue status and priority
- Create issue workflow from the dashboard
- Update issue status directly from the issue register
- Docker Compose deployment with MongoDB and the web application
- Seed data included for immediate demonstration
- Documentation for architecture, API usage, deployment, and testing

## Technology Stack

| Area | Technology |
|---|---|
| Backend | ASP.NET Core / .NET 10 |
| Database | MongoDB |
| Data Access | MongoDB.Driver |
| Frontend | HTML, CSS, JavaScript |
| Deployment | Docker, Docker Compose |
| Hosting Path | IIS or AWS-ready via published .NET app/container |

## Project Structure

```text
ConstructTrack/
├── Dockerfile
├── docker-compose.yml
├── README.md
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   └── TESTING.md
├── scripts/
│   ├── smoke-test.ps1
│   └── smoke-test.sh
└── src/
    └── ConstructTrack.Web/
        ├── Data/
        ├── Dtos/
        ├── Models/
        ├── Services/
        ├── wwwroot/
        ├── Program.cs
        └── ConstructTrack.Web.csproj
```

## Quick Start

### Prerequisites

- Docker Desktop or Docker Engine
- Git

### Run the Application

```bash
git clone <your-repository-url>
cd ConstructTrack
docker compose up --build
```

Open the application:

```text
http://localhost:8080
```

Health check:

```text
http://localhost:8080/health
```

Stop the application:

```bash
docker compose down
```

Remove the database volume and reset seed data:

```bash
docker compose down -v
```

## Local Development Without Docker

Start MongoDB locally on port `27017`, then run:

```bash
cd src/ConstructTrack.Web
dotnet restore
dotnet run
```

Default local database:

```text
constructtrack_dev
```

## Main API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service health check |
| GET | `/api/dashboard` | Dashboard statistics |
| GET | `/api/projects` | List projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/{projectId}/assets` | List project assets |
| POST | `/api/assets` | Create asset |
| GET | `/api/projects/{projectId}/issues` | List project issues |
| POST | `/api/issues` | Create issue |
| PUT | `/api/issues/{id}/status` | Update issue status |
| PUT | `/api/issues/{id}/assignment` | Update assignment |
| DELETE | `/api/issues/{id}` | Delete issue |

Full details are available in `docs/API.md`.

## Portfolio Positioning

This project demonstrates practical skills in:

- Full-stack web development
- ASP.NET Core API design
- MongoDB data modelling
- REST API integration
- Frontend dashboard development
- Construction and infrastructure workflow understanding
- BIM-style asset linking
- Docker-based deployment
- Technical documentation
- Testing and debugging workflow

## Resume Bullet

Developed ConstructTrack, a full-stack construction issue and BIM asset coordination portal using ASP.NET Core, JavaScript, HTML/CSS, MongoDB, and Docker, supporting REST APIs, project dashboards, issue workflow tracking, BIM-style asset linking, filtering, seed data, deployment documentation, and smoke testing.
