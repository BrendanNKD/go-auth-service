# Go Auth Service

Authentication service. This repository ships the Go service, Docker image, and GitHub Actions workflows that build, scan, and deploy the service to AWS ECS.

## Release Information

<!-- release-start -->
- Latest version: v1.2.0
- Release date (UTC): 2026-04-29
<!-- release-end -->

## Versioning

Version bumps are derived from branch prefixes when building releases:
- `major/` or `breaking/` → major version bump.
- `minor/` or `feat/` → minor version bump.
- `patch/` or `fix/` → patch version bump.


## Integration Docs

- [Valkey session check for Python services](docs/valkey-session-check-for-python-services.md)
- [Frontend load balancer demo page](docs/frontend-load-balancer-demo.md)

## Container
podman/docker run --network devnet --env-file .env --name auth-service -p 8080:8080 auth-service

podman/docker build -t auth-service .

