# Go Auth Service

Authentication service. This repository ships the Go service, Docker image, and GitHub Actions workflows that build, scan, and deploy the service to AWS ECS.

## Release Information

<!-- release-start -->
- Latest version: v1.0.9
- Release date (UTC): 2026-02-01
<!-- release-end -->

## Versioning

Version bumps are derived from branch prefixes when building releases:
- `major/` or `breaking/` → major version bump.
- `minor/` or `feat/` → minor version bump.
- `patch/` or `fix/` → patch version bump.


## Container
podman/docker run --network devnet --env-file .env --name auth-service -p 8080:8080 auth-service

podman/docker build -t auth-service .

