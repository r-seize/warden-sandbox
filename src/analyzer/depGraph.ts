import * as fs from 'node:fs';
import * as path from 'node:path';
import { LockfileData } from '../policy/lockfile';

export interface DepNode {
  key: string;
  name: string;
  version: string;
  capabilities: string[];
  deps: string[];  // "pkg@version" keys of direct dependencies
}

export type DepGraph = Map<string, DepNode>;

export function buildDepGraph(nodeModulesDir: string, lockfile: LockfileData): DepGraph {
  const graph: DepGraph = new Map();

  for (const [key, policy] of Object.entries(lockfile.packages)) {
    const atIdx = key.lastIndexOf('@');
    const name = key.slice(0, atIdx);
    const version = key.slice(atIdx + 1);

    // Find package dir
    const pkgDir = name.startsWith('@')
      ? path.join(nodeModulesDir, ...name.split('/'))
      : path.join(nodeModulesDir, name);

    // Read package.json for its dependencies
    let deps: string[] = [];
    try {
      const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')) as {
        dependencies?: Record<string, string>;
      };
      const depNames = Object.keys(pkgJson.dependencies ?? {});
      deps = depNames.flatMap(depName => {
        // Resolve to the actually installed version by reading the dep's own package.json
        let installedKey: string | undefined;
        try {
          const depPkgPath = depName.startsWith('@')
            ? path.join(nodeModulesDir, ...depName.split('/'), 'package.json')
            : path.join(nodeModulesDir, depName, 'package.json');
          const depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf8')) as { version?: string };
          if (depPkg.version) installedKey = `${depName}@${depPkg.version}`;
        } catch { /* dep may not be installed or package.json missing */ }

        const depKey = installedKey && lockfile.packages[installedKey]
          ? installedKey
          : Object.keys(lockfile.packages).find(k => {
              const i = k.lastIndexOf('@');
              return k.slice(0, i) === depName;
            });
        return depKey ? [depKey] : [];
      });
    } catch { /* package.json missing or unreadable */ }

    graph.set(key, {
      key,
      name,
      version,
      capabilities: policy.capabilities,
      deps,
    });
  }

  return graph;
}
