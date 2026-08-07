// Single-module Go provider for Tegami.
//
// tegami/plugins/go fails on modern toolchains: `go mod edit -json` emits
// `"Require": null` / `"Replace": null`, and the plugin's typia schema rejects
// that, so discovery finds nothing (tegami ≤ 1.3.3). This keeps the same
// contract for one root module until upstream accepts null fields:
//
//   package name = go.mod module path
//   version      = newest git tag `v*`
//   publish      = git tag `vX.Y.Z` via GitTagPublishTask + github()
//
// No TypeScript parameter properties: Node strip-only mode rejects them.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import semver from "semver";
import { x } from "tinyexec";
import { WorkspacePackage, type TegamiPlugin } from "tegami";
import { GitTagPublishTask } from "tegami/plugins/git";

const LOCK_KEY = "go-root:version";

export class RootGoPackage extends WorkspacePackage {
  readonly manager = "go";
  readonly path: string;
  readonly name: string;
  private versionValue: string;

  constructor(path: string, name: string, version: string) {
    super();
    this.path = path;
    this.name = name;
    this.versionValue = version;
  }

  get version(): string {
    return this.versionValue;
  }

  setVersion(version: string): void {
    this.versionValue = version;
  }
}

class RootGoPublishTask extends GitTagPublishTask<RootGoPackage> {}

function withV(version: string): string {
  return version.startsWith("v") ? version : `v${version}`;
}

function withoutV(version: string): string {
  return version.startsWith("v") ? version.slice(1) : version;
}

async function readModulePath(cwd: string): Promise<string> {
  const text = await readFile(join(cwd, "go.mod"), "utf8");
  const match = /^module\s+(\S+)/m.exec(text);
  if (!match?.[1]) {
    throw new Error("scripts/tegami-go-root: could not parse module path from go.mod");
  }
  return match[1];
}

async function readLatestVersion(cwd: string): Promise<string> {
  const result = await x(
    "git",
    ["tag", "--list", "v*", "--sort=-v:refname"],
    { nodeOptions: { cwd } },
  );
  if (result.exitCode !== 0) return "0.0.0";
  for (const line of result.stdout.split("\n")) {
    const version = withoutV(line.trim());
    if (semver.valid(version)) return version;
  }
  return "0.0.0";
}

/** Root Go module → `vX.Y.Z` tags + GitHub Release notes. */
export function rootGoModule(): TegamiPlugin {
  let pkg: RootGoPackage | undefined;

  return {
    name: "root-go-module",
    async resolve() {
      pkg = new RootGoPackage(
        this.cwd,
        await readModulePath(this.cwd),
        await readLatestVersion(this.cwd),
      );
      this.graph.add(pkg);
      if (!this.plugins.some((plugin) => plugin.name === "git")) {
        throw new Error(
          'root-go-module requires git (included in github() from "tegami/plugins/github").',
        );
      }
    },
    async applyDraft(draft) {
      if (!pkg) return;
      const bumped = draft.getPackageDraft(pkg.id)?.bumpVersion(pkg);
      if (bumped) pkg.setVersion(bumped);
    },
    initPublishLock({ lock, draft }) {
      if (!pkg || !draft.getPackageDraft(pkg.id)) return;
      lock.write(LOCK_KEY, { version: pkg.version });
    },
    initPublishPlan({ lock, plan }) {
      if (!pkg) return;
      const packagePlan = plan.packages.get(pkg.id);
      if (!packagePlan) return;
      if (packagePlan.updated) {
        const data = lock.read(LOCK_KEY) as { version?: string } | undefined;
        if (typeof data?.version === "string") pkg.setVersion(data.version);
      }
      packagePlan.git ??= {};
      packagePlan.git.tag = withV(pkg.version);
    },
    async publishPreflight({ pkg: candidate }) {
      if (!(candidate instanceof RootGoPackage)) return;
      return { shouldPublish: true };
    },
    publishTasks({ plan }) {
      if (!pkg) return;
      return plan
        .getPackagesToPublish()
        .filter((p): p is RootGoPackage => p instanceof RootGoPackage)
        .map((p) => new RootGoPublishTask(p));
    },
  };
}
