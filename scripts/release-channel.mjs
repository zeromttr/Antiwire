#!/usr/bin/env node
/**
 * Release channels, as the daemon reads them (antiwire-update/src/channel.rs).
 *
 *   node scripts/release-channel.mjs channel 0.3.0-beta.2      prints beta
 *   node scripts/release-channel.mjs newer 0.3.0 0.3.0-rc.1    exits 0 when the first is newer
 *   node scripts/release-channel.mjs nightly-version --base 0.3.0 --released --date 20261102 --run 41
 *                                                             prints 0.3.1-nightly.20261102.41
 *
 * A version with no prerelease is stable, `-beta.N` and `-rc.N` are beta, and `-nightly.…` is
 * nightly. Any other prerelease label is refused, so a release can never land in no channel.
 */

import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u;

const USAGE = `usage:
  release-channel.mjs channel <version>
  release-channel.mjs newer <version> <than>
  release-channel.mjs nightly-version --base <version> [--released] --date <yyyymmdd> --run <n>`;

/** `{ core: [major, minor, patch], pre: string[] }`, or throws for anything but semver. */
export function parseVersion(version) {
  const match = SEMVER.exec(version.trim());
  if (!match) {
    throw new Error(`not a semantic version: ${version}`);
  }
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    pre: match[4] ? match[4].split('.') : [],
  };
}

/** The channel a release of `version` belongs to: `stable`, `beta`, or `nightly`. */
export function channelOf(version) {
  const { pre } = parseVersion(version);
  if (pre.length === 0) return 'stable';
  if (pre[0] === 'beta' || pre[0] === 'rc') return 'beta';
  if (pre[0] === 'nightly') return 'nightly';
  throw new Error(
    `${version} is in no update channel: use -beta.N or -rc.N for beta, -nightly. for nightly`,
  );
}

function compareIdentifiers(a, b) {
  const numericA = /^\d+$/u.test(a);
  const numericB = /^\d+$/u.test(b);
  if (numericA && numericB) return Math.sign(Number(a) - Number(b));
  if (numericA) return -1;
  if (numericB) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Semver precedence: negative when `a` is older than `b`, positive when newer. */
export function compareVersions(a, b) {
  const left = parseVersion(a);
  const right = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    if (left.core[i] !== right.core[i]) return Math.sign(left.core[i] - right.core[i]);
  }
  // A release is newer than any of its prereleases.
  if (left.pre.length === 0 || right.pre.length === 0) {
    return Math.sign(right.pre.length - left.pre.length);
  }
  for (let i = 0; i < Math.min(left.pre.length, right.pre.length); i++) {
    const order = compareIdentifiers(left.pre[i], right.pre[i]);
    if (order !== 0) return order;
  }
  return Math.sign(left.pre.length - right.pre.length);
}

/**
 * The version of a nightly build of `base`, the version the sources state.
 *
 * A nightly sorts after the release it follows. While `base` is unreleased the nightly is a
 * prerelease of it, which sorts below `base` itself. Once `base` is released (`released`), the
 * nightly moves to the next patch, so it is newer than that release.
 */
export function nightlyVersion({ base, released, date, run }) {
  const { core } = parseVersion(base);
  if (!/^\d{8}$/u.test(date)) {
    throw new Error(`date must be yyyymmdd: ${date}`);
  }
  if (!/^[1-9]\d*$/u.test(String(run))) {
    throw new Error(`run must be a positive number: ${run}`);
  }
  const [major, minor, patch] = core;
  const next = released ? [major, minor, patch + 1] : core;
  // Leading zeros are not allowed in a numeric semver identifier; the date has none.
  return `${next.join('.')}-nightly.${date}.${Number(run)}`;
}

function main(argv) {
  const [command, ...rest] = argv;
  if (command === 'channel' && rest.length === 1) {
    console.log(channelOf(rest[0]));
    return 0;
  }
  if (command === 'newer' && rest.length === 2) {
    return compareVersions(rest[0], rest[1]) > 0 ? 0 : 1;
  }
  if (command === 'nightly-version') {
    const { values } = parseArgs({
      args: rest,
      strict: true,
      options: {
        base: { type: 'string' },
        released: { type: 'boolean', default: false },
        date: { type: 'string' },
        run: { type: 'string' },
      },
    });
    if (!values.base || !values.date || !values.run) {
      throw new Error(USAGE);
    }
    console.log(nightlyVersion(values));
    return 0;
  }
  throw new Error(USAGE);
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 2;
  }
}
