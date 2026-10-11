import * as fs from 'node:fs';
import * as path from 'node:path';

export const CONFIG_NAME = '.wardenrc.json';

export interface WardenConfig {
  /** Default profile for `warden run`. */
  profile?: 'strict' | 'default' | 'lenient';
  /** Package names (or name@version keys) excluded from `warden verify` violations. */
  ignore?: string[];
  /** Auto-approve all new packages after `warden install` / `warden update`. */
  autoApprove?: boolean;
  /** Extra registry URL prefixes trusted by `warden integrity`, in addition to the
   *  npm and yarn public registries (e.g. a private registry like Verdaccio or Artifactory). */
  registries?: string[];
}

export function readConfig(projectDir: string): WardenConfig {
  const configPath = path.join(projectDir, CONFIG_NAME);
  if (!fs.existsSync(configPath)) return {};
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8')) as WardenConfig;
  } catch {
    return {};
  }
}

export function isIgnored(pkgKey: string, ignoreList: string[]): boolean {
  if (ignoreList.length === 0) return false;
  const nameEnd = pkgKey.lastIndexOf('@');
  if (nameEnd === -1) return ignoreList.includes(pkgKey);
  const name = pkgKey.slice(0, nameEnd);
  return ignoreList.includes(name) || ignoreList.includes(pkgKey);
}
