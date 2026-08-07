## github.com/minpeter/global-egress@0.0.1

### Container packaging and Tegami-managed releases

Add a distroless Docker image and Compose layout for unprivileged deploys.
Drive versions with Tegami (`.tegami` entries → Version Packages PR → `vX.Y.Z`
tag and GitHub Release), then attach static binaries and push multi-arch images
to GHCR as CI side artifacts.

First public tag is `v0.0.1` (no prior tags → baseline `0.0.0`, patch bump).
