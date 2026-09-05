import { Capability } from '../analyzer/capabilityMap';

export type ViolationMode = 'log' | 'throw' | 'exit';

/** What to do when a violation is detected at runtime. */
export type OnViolationAction = 'log' | 'block' | 'prompt';

export interface ViolationEvent {
  packageName: string;
  capability: Capability;
  apiAccessed: string;
  /** Full stack trace at the point of violation (when captureStack is enabled). */
  stack?: string;
}

export interface ViolationHandlerOptions {
  mode: ViolationMode;
  /** Additional application-level callback invoked before mode-specific action. */
  onViolation?: (event: ViolationEvent) => void;
  /** When true, emit a JSON-structured line to stderr instead of a plain message. */
  jsonLogging?: boolean;
  /** When true, capture and attach a stack trace to every violation event. */
  captureStack?: boolean;
}

export type ViolationFn = (event: ViolationEvent) => void;

/** Format a violation event as a compact JSON log line (ndjson). */
function formatJson(event: ViolationEvent): string {
  return JSON.stringify({
    level: 'warn',
    source: 'warden',
    package: event.packageName,
    capability: event.capability,
    api: event.apiAccessed,
    ...(event.stack ? { stack: event.stack } : {}),
    time: new Date().toISOString(),
  });
}

/**
 * Build the violation handler function used by the module loader hooks.
 *
 * @param opts.mode          'log' emits to stderr, 'throw' raises an Error, 'exit' kills the process.
 * @param opts.onViolation   Optional callback called before the mode action.
 * @param opts.jsonLogging   Emit ndjson to stderr instead of a human-readable message.
 * @param opts.captureStack  Attach a V8 stack trace to each ViolationEvent.
 */
export function createViolationHandler(opts: ViolationHandlerOptions): ViolationFn {
  return (event: ViolationEvent) => {
    // Optionally capture a stack trace and attach it to the event
    if (opts.captureStack && !event.stack) {
      const err = new Error('Warden stack capture');
      // Strip the first two frames (Error constructor + this handler)
      const lines    = (err.stack ?? '').split('\n');
      event          = { ...event, stack: lines.slice(2).join('\n') };
    }

    opts.onViolation?.(event);

    const plainMsg = `[Warden] VIOLATION: ${event.packageName} accessed ${event.apiAccessed} (capability: ${event.capability}) — not declared in policy`;

    switch (opts.mode) {
      case 'log':
        if (opts.jsonLogging) {
          process.stderr.write('\n' + formatJson(event) + '\n');
        } else {
          process.stderr.write('\n' + plainMsg + '\n');
          if (event.stack) {
            process.stderr.write(event.stack + '\n');
          }
        }
        break;

      case 'throw':
        throw Object.assign(new Error(plainMsg), { wardenViolation: true, event });

      case 'exit':
        if (opts.jsonLogging) {
          process.stderr.write('\n' + formatJson(event) + '\n');
        } else {
          process.stderr.write('\n' + plainMsg + '\n');
          if (event.stack) {
            process.stderr.write(event.stack + '\n');
          }
        }
        process.exit(1);
    }
  };
}
