---
packages:
  "github.com/minpeter/global-egress": minor
---

## Container packaging and Tegami-managed releases

Add a distroless Docker image and Compose layout for unprivileged deploys.
Drive versions with Tegami (`.tegami` entries → Version Packages PR → `vX.Y.Z`
tag and GitHub Release), then attach static binaries and push multi-arch images
to GHCR as CI side artifacts.
