// Release manager for global-egress (et.rs pattern).
//
// Tegami owns changelogs, semver bumps, git tags (vX.Y.Z), and GitHub Release
// notes. Static binaries and the GHCR image are built in CI *after* a tag lands
// on main — see .github/workflows/release.yaml.
//
// Flow:
//   1. PR merges with a .tegami/*.md entry
//   2. main CI runs `tegami ci` → opens/updates Version Packages PR
//   3. Merging that PR runs `tegami ci` again → tag + GitHub Release
//   4. Follow-up jobs attach binaries and push multi-arch images
//
// Why not tegami/plugins/go? Current Go toolchains emit null for empty
// require/replace in `go mod edit -json`, and the stock plugin rejects that
// schema so discovery finds nothing. scripts/tegami-go-root.mts implements the
// same single-module tag contract until upstream accepts null fields.

import { tegami } from "tegami";
import { runCli } from "tegami/cli";
import { github } from "tegami/plugins/github";

import { rootGoModule } from "./tegami-go-root.mts";

// package.json is private tooling only. The Go module is the sole publishable
// unit: github.com/minpeter/global-egress → tags vX.Y.Z.
const paper = tegami({
  ignore: ["global-egress-release-tools"],
  plugins: [
    rootGoModule(),
    ...github({
      repo: "minpeter/global-egress",
      versionPr: {
        base: "main",
      },
    }),
  ],
});

await runCli(paper);
