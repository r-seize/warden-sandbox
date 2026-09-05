export type Capability =
  | 'filesystem-read'
  | 'filesystem-write'
  | 'network'
  | 'process-spawn'
  | 'env-access'
  | 'dynamic-code'
  | 'native-binding';

// Modules whose mere require()/import implies a capability unconditionally.
// fs is handled separately because we distinguish read vs write.
export const SENSITIVE_MODULES: Record<string, Capability[]> = {
  net:                  ['network'],
  http:                 ['network'],
  https:                ['network'],
  dns:                  ['network'],
  'dns/promises':       ['network'],
  tls:                  ['network'],
  dgram:                ['network'],
  http2:                ['network'],
  child_process:        ['process-spawn'],
  cluster:              ['process-spawn'],
  worker_threads:       ['process-spawn'],
  vm:                   ['dynamic-code'],
  'node:net':           ['network'],
  'node:http':          ['network'],
  'node:https':         ['network'],
  'node:dns':           ['network'],
  'node:dns/promises':  ['network'],
  'node:tls':           ['network'],
  'node:dgram':         ['network'],
  'node:http2':         ['network'],
  'node:child_process': ['process-spawn'],
  'node:cluster':       ['process-spawn'],
  'node:worker_threads':['process-spawn'],
  'node:vm':            ['dynamic-code'],
};

// fs module names (treated specially: read vs write inferred from method usage)
export const FS_MODULE_NAMES = new Set([
  'fs', 'fs/promises', 'node:fs', 'node:fs/promises',
]);

export const FS_READ_METHODS = new Set([
  'access', 'accessSync',
  'exists', 'existsSync',
  'lstat', 'lstatSync',
  'open', 'openSync',
  'read', 'readSync',
  'readdir', 'readdirSync',
  'readFile', 'readFileSync',
  'readlink', 'readlinkSync',
  'realpath', 'realpathSync',
  'stat', 'statSync',
  'fstat', 'fstatSync',
  'createReadStream',
  'watch', 'watchFile', 'unwatchFile',
  'glob', 'globSync',
  // Directory handle (read-only semantics)
  'opendir', 'opendirSync',
]);

export const FS_WRITE_METHODS = new Set([
  'appendFile', 'appendFileSync',
  'chmod', 'chmodSync', 'fchmod', 'fchmodSync',
  'chown', 'chownSync', 'fchown', 'fchownSync', 'lchown', 'lchownSync',
  'close', 'closeSync',
  'copyFile', 'copyFileSync',
  'cp', 'cpSync',
  'link', 'linkSync',
  'mkdir', 'mkdirSync',
  'mkdtemp', 'mkdtempSync',
  'rename', 'renameSync',
  'rm', 'rmSync',
  'rmdir', 'rmdirSync',
  'symlink', 'symlinkSync',
  'truncate', 'truncateSync', 'ftruncate', 'ftruncateSync',
  'unlink', 'unlinkSync',
  'utimes', 'utimesSync', 'futimes', 'futimesSync',
  'lutimes', 'lutimesSync',
  'write', 'writeSync',
  'writeFile', 'writeFileSync',
  'writev', 'writevSync',
  'createWriteStream',
]);
