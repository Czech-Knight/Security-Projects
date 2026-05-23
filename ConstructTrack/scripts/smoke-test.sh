#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"

echo "Checking health endpoint..."
curl -fsS "$BASE_URL/health" > /dev/null

echo "Checking projects endpoint..."
curl -fsS "$BASE_URL/api/projects" > /dev/null

echo "Checking dashboard endpoint..."
curl -fsS "$BASE_URL/api/dashboard" > /dev/null

echo "Smoke test completed successfully."
