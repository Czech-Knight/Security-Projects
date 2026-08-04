# GitHub and Live Deployment

This guide publishes YashSec Autopilot without committing credentials and without exposing the full scanner engine to anonymous users.

## Deployment model

Use two public endpoints:

1. **GitHub Pages** hosts the static project site from `site/`.
2. **Koyeb** runs the FastAPI application in read-only demo mode from the repository Dockerfile.

GitHub Pages cannot run Python. The dynamic demo must therefore run on a container/web-service platform. The Koyeb free instance is suitable for a portfolio preview, not a production security service.

## What remains local

The full scanner workspace should remain on your approved Windows machine or internal environment. Public demo mode disables:

- arbitrary local, Git, and ZIP repository registration;
- scan creation and cancellation;
- startup command execution;
- dynamic target access;
- auth-profile creation;
- report generation and administrative settings;
- audit and backup administration.

It exposes a randomly provisioned read-only viewer session and a bundled intentionally vulnerable sample only.

## 1. Publish the repository

Create an empty GitHub repository, then run from the cleaned project folder:

```powershell
git init
git add .
git status --short
git commit -m "Initial YashSec Autopilot release"
git branch -M main
git remote add origin https://github.com/<YOUR-USERNAME>/<YOUR-REPOSITORY>.git
git push -u origin main
```

Review `git status` before the first commit. Never force-add ignored files.

## 2. Create the Ollama Cloud key

Create an Ollama account and API key. Do not paste the key into any repository file.

Ollama direct cloud API settings used by this project:

```text
Base URL: https://ollama.com
Authentication: Authorization: Bearer <OLLAMA_API_KEY>
Chat endpoint: /api/chat
```

The configured cloud model must appear in the current Ollama model list. `gpt-oss:20b` is the prepared default; update it if your account exposes a different cloud-capable tag.

## 3. Deploy the read-only backend on Koyeb

In the Koyeb console:

1. Create a **Web Service** from GitHub.
2. Select this repository and the `main` branch.
3. Choose **Dockerfile** as the build method.
4. Select the **Free** instance.
5. Set the HTTP health-check path to `/api/health`.
6. Let Koyeb provide the `PORT` variable; the Docker command reads it automatically.
7. Add the following non-secret environment variables.

```dotenv
YASHSEC_ENV=production
YASHSEC_DOCS_ENABLED=false
YASHSEC_DEMO_MODE=true
YASHSEC_ALLOW_REMOTE_DYNAMIC_SCAN=false
YASHSEC_ALLOW_CLOUD_AI=true
YASHSEC_CLOUD_AI_HOSTS=ollama.com
YASHSEC_OLLAMA_URL=https://ollama.com
YASHSEC_OLLAMA_MODEL=gpt-oss:20b
YASHSEC_DEMO_AI_REQUESTS_PER_HOUR=20
YASHSEC_DEMO_SESSION_REQUESTS_PER_HOUR=30
```

Add this value as a **Secret**, not a normal visible variable:

```dotenv
OLLAMA_API_KEY=<your Ollama API key>
```

Deploy and wait for the health check. Open:

```text
https://<your-koyeb-domain>/api/health
```

Expected fields include `status: ok` and `demo_mode: true`.

Then open the root URL and use **Open read-only live demo**. Confirm that project and scan creation controls are hidden and that the seeded workspace contains only `Vulnerable Demo API`.

## 4. Connect the GitHub Pages button

Copy the Koyeb root URL. In GitHub:

1. Open **Settings → Secrets and variables → Actions → Variables**.
2. Create the repository variable `YASHSEC_LIVE_DEMO_URL`.
3. Set its value to the Koyeb root URL, without a trailing path.
4. Open **Settings → Pages** and select **GitHub Actions** as the source.
5. Run the `Deploy GitHub Pages` workflow or push a change to `main`.

The workflow creates `site/runtime-config.js` during deployment. It automatically sets the GitHub repository link and the live-demo button without committing a deployment URL or secret.

## 5. Validate the deployment

Check the following:

```text
[ ] Pages site loads over HTTPS
[ ] GitHub button points to the correct repository
[ ] Live demo button points to Koyeb
[ ] /api/health reports demo_mode=true
[ ] Demo login creates only a viewer session
[ ] Add project and New scan are not available to the viewer
[ ] Only the bundled demonstration project is visible
[ ] OLLAMA_API_KEY is absent from page source, browser storage, network responses, and repository history
[ ] AI requests fail safely when the key/quota/provider is unavailable
[ ] No private source code is submitted to the public demo
```

## Free-tier reality

At the time this package was prepared, GitHub Pages provided static hosting for eligible repositories, Koyeb offered one small free instance per organisation for hobby/testing, and Ollama Cloud was free to start. These services, limits, account requirements, model availability, and quotas can change. Treat the configuration as a no-cost starting point, not a promise of unlimited permanent hosting.

Koyeb's free instance is small. This is why the hosted mode uses seeded data and does not install Semgrep, Trivy, Gitleaks, Docker-in-Docker, ZAP, or local models.

## Updates and rollback

Every push to `main` can trigger Pages deployment. Configure Koyeb automatic deployment from the same branch for the backend. Use protected branches and pull requests once the repository is public.

For rollback, redeploy a known-good commit in Koyeb and GitHub Actions. Never restore an old `.env`, database, or secret file from Git history.

## Removing the public demo

- Disable or delete the Koyeb service.
- Delete or rotate `OLLAMA_API_KEY`.
- Remove `YASHSEC_LIVE_DEMO_URL` from GitHub repository variables.
- Disable GitHub Pages if the portfolio site should also be removed.
