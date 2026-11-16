import { Capability } from '../analyzer/capabilityMap';
import { PackagePolicy } from './lockfile';

export type ApproveChoice = 'allow' | 'deny' | 'restrict' | 'skip' | 'quit' | 'invalid';

/** Parse a single keystroke/line from `warden approve --interactive` into a choice. */
export function parseApproveChoice(input: string): ApproveChoice {
  const c = input.trim().toLowerCase();
  if (c === 'a') return 'allow';
  if (c === 'd') return 'deny';
  if (c === 'r') return 'restrict';
  if (c === 'q') return 'quit';
  if (c === '' || c === 's') return 'skip';
  return 'invalid';
}

export interface ApplyApproveChoiceResult {
  /** Whether the entry was mutated (and the lockfile needs writing). */
  changed: boolean;
  message: string;
}

/**
 * Apply a parsed interactive-approve choice to a lockfile entry, mutating it
 * in place. Pulled out of the CLI's readline loop so the actual approve/deny/
 * restrict logic can be unit-tested without driving a real TTY — readline's
 * sequential `question()` calls only work reliably against one, so the CLI
 * wiring itself isn't practical to test in this environment.
 */
export function applyApproveChoice(
  entry: PackagePolicy,
  choice: ApproveChoice,
  capability: string | undefined,
  note: string | undefined,
  validCaps: Set<string>,
): ApplyApproveChoiceResult {
  if (choice === 'skip' || choice === 'quit') {
    return { changed: false, message: 'skipped.' };
  }

  if (choice === 'invalid') {
    return { changed: false, message: `Unrecognised choice — skipped.` };
  }

  if (choice === 'allow') {
    entry.status = 'approved';
    delete entry.allowedCapabilities;
  } else {
    // 'deny' or 'restrict'
    if (!capability || !validCaps.has(capability)) {
      return { changed: false, message: `Unknown capability "${capability ?? ''}" — skipped.` };
    }
    entry.status = 'approved';
    if (choice === 'deny') {
      const denied = new Set(entry.deniedCapabilities ?? []);
      denied.add(capability as Capability);
      entry.deniedCapabilities = [...denied];
      delete entry.allowedCapabilities;
    } else {
      entry.allowedCapabilities = [capability as Capability];
    }
  }

  if (note) entry.note = note;
  else delete entry.note;

  return { changed: true, message: 'approved' };
}
