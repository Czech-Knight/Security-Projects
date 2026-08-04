# Changelog

All notable changes are documented here.

## 1.0.0-rc1 — GitHub-ready sanitised release

### Added

- Read-only public portfolio demo mode with bundled seeded evidence.
- Secure Ollama Cloud endpoint validation, host allow-list, server-side API key, and demo rate limiting.
- GitHub Pages portfolio site and deployment workflow.
- Koyeb-ready Docker deployment instructions.
- Fresh product screenshots and repository hygiene scanner.
- CodeQL, Dependabot, community files, and sanitisation documentation.

### Security

- Removed virtual environments, runtime databases, logs, caches, local configuration, personal history, and bundled scanner executables from the distributable repository.
- Prevented remote AI use without explicit cloud opt-in, HTTPS, and host approval.
- Preserved viewer RBAC correctly during database seeding.
- Disabled scheduler and mutation-heavy workflows in demo mode.

### Changed

- Docker Compose now uses the official Ollama image and persists model data separately.
- Public deployment is explicitly a read-only showcase rather than a multi-tenant scanner service.
