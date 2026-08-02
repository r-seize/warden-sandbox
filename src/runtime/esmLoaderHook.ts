import { MessageChannel } from 'node:worker_threads';
import { pathToFileURL } from 'node:url';
import * as path from 'node:path';
import { LockfileData } from '../policy/lockfile';
import { ViolationFn, ViolationEvent } from './violationHandler';
import type { Profile } from './moduleLoaderHook';

// module.register() is available since Node.js 20.6 / 18.19.
// @types/node may not have it depending on version — cast to any.
const nodeModule = require('node:module') as {
  register(specifier: string, options: {
    parentURL: string;
    data: unknown;
    transferList?: object[];
  }): void;
};

// Returns a cleanup function — call it after the script finishes to let the
// process exit (port1.ref() would otherwise keep the event loop alive).
export function installEsmLoaderHook(
  lockfile: LockfileData,
  enforce: boolean,
  onViolation: ViolationFn,
  profile: Profile = 'default',
): () => void {
  if (!nodeModule.register) {
    process.stderr.write(
      '[Warden] Warning: module.register() not available (requires Node.js >= 18.19). ESM hooks disabled.\n',
    );
    return () => {};
  }

  const { port1, port2 } = new MessageChannel();

  // port1 stays in main thread: receives violation events from loader thread
  port1.on('message', (event: ViolationEvent) => {
    onViolation(event);
  });
  // ref() keeps the event loop alive during script execution so we receive events
  port1.ref();

  const hooksFile = path.join(__dirname, 'esmHooks.mjs');
  const hooksURL = pathToFileURL(hooksFile).href;

  nodeModule.register(hooksURL, {
    parentURL: pathToFileURL(__filename).href,
    data: { lockfile, enforce, port: port2, profile },
    transferList: [port2 as unknown as object],
  });

  // Cleanup: unref so the event loop can exit after the script finishes
  return () => {
    port1.unref();
    port1.removeAllListeners();
  };
}
