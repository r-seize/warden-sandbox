import { describe, it, expect } from 'vitest';
import { scanFile } from '../src/analyzer/astScanner';
import type { Capability } from '../src/analyzer/capabilityMap';

function caps(source: string): Capability[] {
  return [...scanFile(source).capabilities].sort();
}

function isUnanalyzable(source: string): boolean {
  return scanFile(source).unanalyzable;
}

// ─── filesystem-read ─────────────────────────────────────────────────────────

describe('filesystem-read', () => {
  it('detects require("fs") + readFile call', () => {
    const result = caps(`
      const fs = require('fs');
      fs.readFile('/etc/passwd', 'utf8', cb);
    `);
    expect(result).toContain('filesystem-read');
    expect(result).not.toContain('filesystem-write');
  });

  it('detects require("node:fs") alias', () => {
    const result = caps(`const fs = require('node:fs'); fs.stat('/tmp', cb);`);
    expect(result).toContain('filesystem-read');
  });

  it('detects destructured read method', () => {
    const result = caps(`
      const { readFile, stat } = require('fs');
      readFile('./config.json', 'utf8', cb);
    `);
    expect(result).toContain('filesystem-read');
    expect(result).not.toContain('filesystem-write');
  });

  it('detects inline require().method()', () => {
    const result = caps(`require('fs').createReadStream('./data.csv')`);
    expect(result).toContain('filesystem-read');
  });

  it('detects fs/promises read', () => {
    const result = caps(`
      const fsp = require('fs/promises');
      fsp.readFile('./foo');
    `);
    expect(result).toContain('filesystem-read');
  });

  it('conservative: bare require("fs") with no method calls still flags read', () => {
    // We don't know what the caller does with the module object — conservative
    const result = caps(`const x = require('fs');`);
    expect(result).toContain('filesystem-read');
  });
});

// ─── filesystem-write ────────────────────────────────────────────────────────

describe('filesystem-write', () => {
  it('detects writeFile', () => {
    const result = caps(`
      const fs = require('fs');
      fs.writeFile('/tmp/out.txt', data, cb);
    `);
    expect(result).toContain('filesystem-write');
    expect(result).toContain('filesystem-read'); // conservative: read also set when fs required
  });

  it('detects destructured writeFile', () => {
    const result = caps(`
      const { writeFile } = require('fs');
      writeFile('./output', content);
    `);
    expect(result).toContain('filesystem-write');
  });

  it('detects inline require().unlink()', () => {
    const result = caps(`require('fs').unlink('/tmp/stale', cb);`);
    expect(result).toContain('filesystem-write');
  });

  it('detects createWriteStream', () => {
    const result = caps(`
      const fs        = require('fs');
      const stream    = fs.createWriteStream('./log.txt');
    `);
    expect(result).toContain('filesystem-write');
  });

  it('detects mkdir', () => {
    const result = caps(`const fs = require('fs'); fs.mkdir('./build', { recursive: true }, cb);`);
    expect(result).toContain('filesystem-write');
  });
});

// ─── network ─────────────────────────────────────────────────────────────────

describe('network', () => {
  it('detects require("http")', () => {
    const result = caps(`
      const http = require('http');
      http.get('http://example.com', cb);
    `);
    expect(result).toContain('network');
  });

  it('detects require("https")', () => {
    const result = caps(`const https = require('https'); https.request(opts, cb);`);
    expect(result).toContain('network');
  });

  it('detects require("net")', () => {
    const result = caps(`const net = require('net'); net.createConnection(80, 'host', cb);`);
    expect(result).toContain('network');
  });

  it('detects require("dns")', () => {
    const result = caps(`const dns = require('dns'); dns.lookup('example.com', cb);`);
    expect(result).toContain('network');
  });

  it('detects node: prefix', () => {
    const result = caps(`const http = require('node:http'); http.get('/');`);
    expect(result).toContain('network');
  });

  it('detects tls', () => {
    const result = caps(`const tls = require('tls'); tls.connect(443, 'host');`);
    expect(result).toContain('network');
  });
});

// ─── process-spawn ───────────────────────────────────────────────────────────

describe('process-spawn', () => {
  it('detects require("child_process")', () => {
    const result = caps(`
      const cp = require('child_process');
      cp.exec('ls -la', cb);
    `);
    expect(result).toContain('process-spawn');
  });

  it('detects destructured exec', () => {
    const result = caps(`const { exec } = require('child_process'); exec('whoami');`);
    expect(result).toContain('process-spawn');
  });

  it('detects worker_threads', () => {
    const result = caps(`const { Worker } = require('worker_threads');`);
    expect(result).toContain('process-spawn');
  });
});

// ─── env-access ──────────────────────────────────────────────────────────────

describe('env-access', () => {
  it('detects process.env', () => {
    const result = caps(`const token = process.env.NPM_TOKEN;`);
    expect(result).toContain('env-access');
  });

  it('detects process["env"] computed access', () => {
    const result = caps(`const val = process['env']['HOME'];`);
    // computed member expression — property is a Literal 'env'
    expect(result).toContain('env-access');
  });

  it('detects destructured process.env', () => {
    const result = caps(`const { HOME, PATH } = process.env;`);
    expect(result).toContain('env-access');
  });

  it('detects assignment from process.env', () => {
    const result = caps(`const env = process.env; const token = env.TOKEN;`);
    expect(result).toContain('env-access');
  });
});

// ─── dynamic-code ────────────────────────────────────────────────────────────

describe('dynamic-code', () => {
  it('detects eval()', () => {
    const result = caps(`eval("console.log(1)");`);
    expect(result).toContain('dynamic-code');
  });

  it('detects new Function()', () => {
    const result = caps(`const fn = new Function('a', 'return a + 1');`);
    expect(result).toContain('dynamic-code');
  });

  it('detects require("vm")', () => {
    const result = caps(`const vm = require('vm'); vm.runInNewContext('1+1');`);
    expect(result).toContain('dynamic-code');
  });

  it('does not flag normal function calls as dynamic', () => {
    const result = caps(`function foo() { return 42; } foo();`);
    expect(result).not.toContain('dynamic-code');
  });
});

// ─── unanalyzable ─────────────────────────────────────────────────────────────

describe('unanalyzable', () => {
  it('flags completely invalid JS as unanalyzable', () => {
    expect(isUnanalyzable(`this is not javascript @@@ !!!`)).toBe(true);
  });

  it('does not flag valid JS as unanalyzable', () => {
    expect(isUnanalyzable(`const x = 1;`)).toBe(false);
  });

  it('handles empty files without error', () => {
    expect(isUnanalyzable('')).toBe(false);
    expect(caps('')).toEqual([]);
  });

  it('handles files with only comments', () => {
    expect(isUnanalyzable('// just a comment\n/* nothing here */')).toBe(false);
  });
});

// ─── no false positives ──────────────────────────────────────────────────────

describe('no false positives on innocuous code', () => {
  it('clean utility function has no capabilities', () => {
    const result = caps(`
      function leftPad(str, len, ch) {
        ch                              = ch || ' ';
        while (str.length < len) str    = ch + str;
        return str;
      }
      module.exports = leftPad;
    `);
    expect(result).toEqual([]);
  });

  it('string containing "require" is not flagged', () => {
    const result = caps(`const msg = "please require your badge"; console.log(msg);`);
    expect(result).toEqual([]);
  });

  it('require.resolve is not treated as a module require', () => {
    const result = caps(`const p = require.resolve('some-module');`);
    // require.resolve is a MemberExpression, not a direct require call
    expect(result).toEqual([]);
  });
});

// ─── combined capabilities ────────────────────────────────────────────────────

describe('combined capabilities in one file', () => {
  it('detects multiple capabilities', () => {
    const result = caps(`
      const https       = require('https');
      const { exec }    = require('child_process');
      const token       = process.env.SECRET;
      eval('1+1');
    `);
    expect(result).toContain('network');
    expect(result).toContain('process-spawn');
    expect(result).toContain('env-access');
    expect(result).toContain('dynamic-code');
  });
});
