import { Capability } from '../analyzer/capabilityMap';

export type ViolationMode = 'log' | 'throw' | 'exit';

export interface ViolationEvent {
  packageName: string;
  capability: Capability;
  apiAccessed: string;
  stack?: string;
}

export interface ViolationHandlerOptions {
  mode: ViolationMode;
  onViolation?: (event: ViolationEvent) => void;
}

export type ViolationFn = (event: ViolationEvent) => void;

export function createViolationHandler(opts: ViolationHandlerOptions): ViolationFn {
  return (event: ViolationEvent) => {
    opts.onViolation?.(event);

    const msg = `[Warden] VIOLATION: ${event.packageName} accessed ${event.apiAccessed} (capability: ${event.capability}) — not declared in policy`;

    switch (opts.mode) {
      case 'log':
        process.stderr.write('\n' + msg + '\n');
        break;

      case 'throw':
        throw new Error(msg);

      case 'exit':
        process.stderr.write('\n' + msg + '\n');
        process.exit(1);
    }
  };
}
