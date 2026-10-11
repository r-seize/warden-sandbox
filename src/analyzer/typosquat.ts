/**
 * Lightweight, fully offline typosquat heuristic: flags a package name that is
 * one single-character edit (insert/delete/substitute/transpose) away from a
 * well-known popular package, without being an exact match itself.
 *
 * This is intentionally conservative — a loud false positive on every scan
 * erodes trust in the tool faster than a missed detection. Distance is capped
 * at 1 and the popular-package list is small and curated, so recall is low
 * but precision is high. Scoped packages ("@scope/name") are skipped: the
 * heuristic only covers the classic flat-name typosquat pattern.
 */

// A small, static list of widely-used unscoped packages. Not exhaustive —
// extending it is safe (more true positives) but keep entries unscoped and
// genuinely popular to avoid flagging legitimate near-neighbours.
export const POPULAR_PACKAGES = [
  'lodash', 'react', 'react-dom', 'express', 'axios', 'chalk', 'commander',
  'webpack', 'babel-core', 'eslint', 'typescript', 'moment', 'request', 'async',
  'underscore', 'debug', 'colors', 'glob', 'minimist', 'yargs', 'inquirer',
  'rxjs', 'redux', 'vue', 'jquery', 'bluebird', 'uuid', 'dotenv', 'cors',
  'body-parser', 'mongoose', 'sequelize', 'pg', 'mysql2', 'redis', 'ioredis',
  'socket.io', 'ws', 'jest', 'mocha', 'chai', 'sinon', 'nodemon', 'pm2',
  'dayjs', 'semver', 'ora', 'figlet', 'prompts', 'fs-extra', 'rimraf',
  'mkdirp', 'minimatch', 'micromatch', 'cross-env', 'immutable', 'ramda',
  'classnames', 'prop-types', 'styled-components', 'next', 'nuxt', 'gatsby',
  'vite', 'rollup', 'esbuild', 'parcel', 'tslib', 'core-js', 'regenerator-runtime',
  'is-promise', 'is-array', 'is-object', 'through2', 'readable-stream',
  'node-fetch', 'got', 'superagent', 'ky', 'undici', 'cheerio', 'puppeteer',
  'playwright', 'sharp', 'multer', 'passport', 'jsonwebtoken', 'bcrypt',
  'bcryptjs', 'joi', 'zod', 'yup', 'ajv', 'winston', 'pino', 'morgan',
  'helmet', 'compression', 'cookie-parser', 'express-session', 'nanoid',
  'shortid', 'qs', 'form-data', 'tar', 'tar-fs', 'adm-zip', 'archiver',
  'sharp', 'canvas', 'moment-timezone', 'date-fns', 'luxon', 'validator',
  'sanitize-html', 'xss', 'marked', 'highlight.js', 'prismjs', 'eventemitter3',
  'ws', 'socket.io-client', 'graphql', 'apollo-server', 'grpc', 'protobufjs',
  'commander', 'meow', 'yargs-parser', 'chokidar', 'globby', 'fast-glob',
  'execa', 'cross-spawn', 'which', 'shelljs', 'concurrently', 'npm-run-all',
  'husky', 'lint-staged', 'prettier', 'eslint-config-prettier', 'ts-node', 'tsx',
  'vitest', 'jasmine', 'karma', 'cypress', 'supertest', 'nock', 'proxyquire',
  'sinon-chai', 'chai-as-promised', 'webpack-cli', 'webpack-dev-server',
  'babel-loader', 'css-loader', 'style-loader', 'file-loader', 'url-loader',
  'postcss', 'autoprefixer', 'tailwindcss', 'sass', 'less', 'stylus',
];

const POPULAR_SET = new Set(POPULAR_PACKAGES);

/**
 * Damerau-Levenshtein edit distance (optimal string alignment variant):
 * insert, delete, substitute, or transpose two adjacent characters, each
 * costing 1. Transposition matters here because swapped-letter typos
 * ("lodahs" for "lodash") are one of the most common typosquat patterns.
 */
function editDistance(a: string, b: string, maxDistance: number): number {
  if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1;

  const d: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) d[i][0] = i;
  for (let j = 0; j <= b.length; j++) d[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost    = a[i - 1] === b[j - 1] ? 0 : 1;
      let best      = Math.min(
        d[i - 1][j] + 1,       // deletion
        d[i][j - 1] + 1,       // insertion
        d[i - 1][j - 1] + cost, // substitution (or match)
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, d[i - 2][j - 2] + 1); // adjacent transposition
      }
      d[i][j] = best;
    }
  }
  return d[a.length][b.length];
}

const MIN_NAME_LENGTH    = 4; // skip very short names ("fs", "ms") — too noisy
const MAX_EDIT_DISTANCE  = 1;

/**
 * Check whether `pkgName` looks like a one-character typo of a popular package.
 * Returns the popular package name it may be squatting on, or null.
 */
export function detectTyposquat(pkgName: string): string | null {
  if (pkgName.startsWith('@')) return null; // scoped packages not covered
  if (pkgName.length < MIN_NAME_LENGTH) return null;
  if (POPULAR_SET.has(pkgName)) return null; // exact match — not a typo of itself

  for (const popular of POPULAR_PACKAGES) {
    if (editDistance(pkgName, popular, MAX_EDIT_DISTANCE) <= MAX_EDIT_DISTANCE) {
      return popular;
    }
  }
  return null;
}
