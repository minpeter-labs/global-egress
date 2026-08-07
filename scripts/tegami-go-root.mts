// Single-module Go provider for Tegami.
//
// tegami/plugins/go fails on modern toolchains: `go mod edit -json` emits
// `"Require": null` / `"Replace": null`, and the plugin's typia schema only
// accepts omitted or array values, so discovery returns zero packages (tegami
// 1.3.3). This plugin keeps the same release contract without that path:
//
//   - package name = go.mod module path
//   - version source = existing git tags `v*`
//   - publish = git tag `vX.Y.Z` (via GitTagPublishTask + github/git plugins)
//
// Written without TypeScript parameter properties so `node scripts/*.mts` works
// under Node's strip-only type stripping.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import semver from "semver";
import { x } from "tinyexec";
import {
  WorkspacePackage,
  type PackagePublishResult,
  type TegamiPlugin,
} from "tegami";
import { GitTagPublishTask } from "tegami/plugins/git";

const LOCK_KEY = "go-root:packages";

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

interface LockedPackage {
  id: string;
  version: string;
}

function formatTag(version: string): string {
  return version.startsWith("v") ? version : `v${version}`;
}

function stripV(version: string): string {
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
    const version = stripV(line.trim());
    if (semver.valid(version)) return version;
  }
  return "0.0.0";
}

/** Tegami plugin: root Go module → `vX.Y.Z` tags + GitHub Release notes. */
export function rootGoModule(): TegamiPlugin {
  let pkg: RootGoPackage | undefined;

  return {
    name: "root-go-module",
    async resolve() {
      const name = await readModulePath(this.cwd);
      const version = await readLatestVersion(this.cwd);
      pkg = new RootGoPackage(this.cwd, name, version);
      this.graph.add(pkg);
      if (!this.plugins.some((plugin) => plugin.name === "git")) {
        throw new Error(
          'root-go-module requires the git plugin (included in github() from "tegami/plugins/github").',
        );
      }
    },
    async applyDraft(draft) {
      if (!pkg) return;
      const bumped = draft.getPackageDraft(pkg.id)?.bumpVersion(pkg);
      if (bumped) pkg.setVersion(bumped);
    },
    initPublishLock({ lock, draft }) {
      if (!pkg) return;
      if (!draft.getPackageDraft(pkg.id)) return;
      const entry: LockedPackage = { id: pkg.id, version: pkg.version };
      lock.write(LOCK_KEY, entry);
    },
    initPublishPlan({ lock, plan }) {
      if (!pkg) return;
      const versions = new Map<string, string>();
      let data: unknown;
      while ((data = lock.read(LOCK_KEY))) {
        const entry = data as LockedPackage;
        if (typeof entry?.id === "string" && typeof entry?.version === "string") {
          versions.set(entry.id, entry.version);
        }
      }
      for (const [id, packagePlan] of plan.packages) {
        if (id !== pkg.id) continue;
        const version = packagePlan.updated ? versions.get(id) : undefined;
        if (version) pkg.setVersion(version);
        packagePlan.git ??= {};
        packagePlan.git.tag = formatTag(pkg.version);
      }
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
    async publish({ pkg: candidate }): Promise<PackagePublishResult | undefined> {
      if (!(candidate instanceof RootGoPackage)) return;
      return { type: "published" };
    },
  };
}
