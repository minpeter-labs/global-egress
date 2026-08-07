// Release manager for global-egress (et.rs pattern).
//
// Tegami: changelogs, semver, vX.Y.Z tags, GitHub Release notes.
// CI after a tag: static binaries + multi-arch GHCR (.github/workflows/release.yaml).
//
// Why not tegami/plugins/go? Modern `go mod edit -json` emits null for empty
// require/replace; stock discovery fails. scripts/tegami-go-root.mts covers the
// single-module tag contract until upstream accepts null fields.

import { tegami } from "tegami";
import { runCli } from "tegami/cli";
import { github } from "tegami/plugins/github";

import { rootGoModule } from "./tegami-go-root.mts";

const repo =
  process.env.GITHUB_REPOSITORY ?? "minpeter/global-egress";

const paper = tegami({
  ignore: ["global-egress-release-tools"],
  plugins: [
    rootGoModule(),
    ...github({
      repo,
      versionPr: {
        base: "main",
      },
    }),
  ],
});

await runCli(paper);
