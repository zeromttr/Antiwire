#!/usr/bin/env node
/**
 * Describes and signs a release for the self-updater.
 *
 *   node scripts/release-manifest.mjs generate-key
 *   ANTIWIRE_UPDATE_SIGNING_KEY=<seed> node scripts/release-manifest.mjs build \
 *     --version 0.2.0 --notes-file notes.md --out dist \
 *     --platform windows-x86_64 --daemon antiwire-daemon-0.2.0-windows-x86_64.exe \
 *       --client antiwire-0.2.0-windows-x86_64.exe \
 *     --platform macos-aarch64 --daemon antiwire-daemon-0.2.0-macos-aarch64 \
 *       --client Antiwire-0.2.0-macos-aarch64.app.zip
 *
 * `--platform`, `--daemon`, and `--client` repeat once per platform, in that order. On
 * macOS the client is the app bundle zipped with `ditto -c -k --keepParent`.
 *
 * `build` writes DIR/manifest.json and DIR/manifest.json.sig, the two assets the daemon
 * downloads from the latest GitHub release. The JSON must match `Manifest` in
 * antiwire-update/src/manifest.rs, which rejects unknown fields. The signature is a raw
 * 64-byte ed25519 signature over the exact bytes of manifest.json.
 *
 *   ANTIWIRE_UPDATE_SIGNING_KEY=<seed> node scripts/release-manifest.mjs packages \
 *     --version 0.2.0 --notes-file notes.md --out dist \
 *     --platform linux-x86_64 --deb antiwire_0.2.0_amd64.deb \
 *       --rpm antiwire-0.2.0-1.x86_64.rpm
 *
 * `packages` writes DIR/manifest-linux.json and its .sig the same way, for Linux daemons,
 * which install the release's .deb or .rpm. It must match `PackageManifest` in
 * antiwire-update/src/package.rs. It is a separate file because adding packages to
 * manifest.json would make every daemon already installed reject it.
 */

import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

/** PKCS#8 DER prefix for an ed25519 private key (RFC 8410); the 32-byte seed follows it. */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const MAX_NOTES = 2000;
const VERSION_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const PLATFORM_PATTERN = /^[a-z0-9_]+-[a-z0-9_]+$/u;

const USAGE = `usage:
  release-manifest.mjs generate-key
  release-manifest.mjs build --version <x.y.z> --notes-file <file> --out <dir> \\
    (--platform <os-arch> --daemon <file> --client <file>)...
  release-manifest.mjs packages --version <x.y.z> --notes-file <file> --out <dir> \\
    (--platform <linux-arch> --deb <file> --rpm <file>)...`;

/** Package formats a Linux release publishes, as `PackageFormat` in package.rs names them. */
const PACKAGE_FORMATS = new Set(['deb', 'rpm']);

/** A new keypair as base64: the 32-byte seed (secret) and the 32-byte raw public key. */
export function generateKeys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    seed: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('base64'),
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64'),
  };
}

/** The signing key for a base64 seed. Refuses a missing or malformed seed. */
export function privateKeyFromSeed(seedBase64) {
  if (!seedBase64) {
    throw new Error(
      'ANTIWIRE_UPDATE_SIGNING_KEY is not set; refusing to build an unsigned release',
    );
  }
  const seed = Buffer.from(seedBase64, 'base64');
  if (seed.length !== 32) {
    throw new Error(
      'ANTIWIRE_UPDATE_SIGNING_KEY must be the 32-byte base64 seed from generate-key',
    );
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

/** Name, hash, and size of one release file. */
async function describeFile(what, path) {
  if (!(await stat(path)).isFile()) {
    throw new Error(`${what} is not a file: ${path}`);
  }
  const bytes = await readFile(path);
  return {
    name: basename(path),
    sha256: createHash('sha256').update(bytes).digest('hex'),
    size: bytes.length,
  };
}

async function manifestFile(role, platform, path) {
  return { role, platform, ...(await describeFile(role, path)) };
}

function checkVersion(version) {
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`not a semantic version: ${version}`);
  }
}

/** The notes as published: trimmed, non-empty, and within the daemon's limit. */
function checkedNotes(notes) {
  const trimmed = notes.trim();
  if (trimmed.length === 0) {
    throw new Error('release notes are empty');
  }
  if ([...trimmed].length > MAX_NOTES) {
    throw new Error(`release notes are longer than ${MAX_NOTES} characters`);
  }
  return trimmed;
}

/** Writes `name` and `name.sig` into `outDir`. */
async function writeSigned(outDir, name, manifest, privateKey) {
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const signature = sign(null, bytes, privateKey);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, name), bytes);
  await writeFile(join(outDir, `${name}.sig`), signature);
}

/**
 * Writes `manifest.json` and `manifest.json.sig` into `outDir` and returns the manifest.
 * Throws before writing anything when an input is invalid.
 */
export async function buildRelease({ version, notes, builds, outDir, privateKey }) {
  checkVersion(version);
  if (builds.length === 0) {
    throw new Error('a release needs at least one platform');
  }
  const platforms = new Set();
  for (const { platform } of builds) {
    if (!PLATFORM_PATTERN.test(platform)) {
      throw new Error(`platform must look like windows-x86_64: ${platform}`);
    }
    // The Rust verifier rejects a role listed twice for one platform.
    if (platforms.has(platform)) {
      throw new Error(`platform listed twice: ${platform}`);
    }
    platforms.add(platform);
  }
  const manifest = {
    version,
    notes: checkedNotes(notes),
    files: [],
  };
  for (const { platform, daemon, client } of builds) {
    manifest.files.push(await manifestFile('daemon', platform, daemon));
    manifest.files.push(await manifestFile('client', platform, client));
  }
  await writeSigned(outDir, 'manifest.json', manifest, privateKey);
  return manifest;
}

/**
 * Writes `manifest-linux.json` and `manifest-linux.json.sig` into `outDir` and returns the
 * manifest. `packages` lists `{ platform, format, file }`. Throws before writing anything
 * when an input is invalid.
 */
export async function buildPackageManifest({ version, notes, packages, outDir, privateKey }) {
  checkVersion(version);
  if (packages.length === 0) {
    throw new Error('a Linux release needs at least one package');
  }
  const seen = new Set();
  for (const { platform, format } of packages) {
    if (!PLATFORM_PATTERN.test(platform) || !platform.startsWith('linux-')) {
      throw new Error(`platform must look like linux-x86_64: ${platform}`);
    }
    if (!PACKAGE_FORMATS.has(format)) {
      throw new Error(`package format must be deb or rpm: ${format}`);
    }
    // The Rust verifier rejects a format listed twice for one platform.
    const key = `${platform}/${format}`;
    if (seen.has(key)) {
      throw new Error(`.${format} listed twice for ${platform}`);
    }
    seen.add(key);
  }

  const manifest = {
    version,
    notes: checkedNotes(notes),
    packages: [],
  };
  for (const { platform, format, file } of packages) {
    manifest.packages.push({ platform, format, ...(await describeFile(`.${format}`, file)) });
  }
  await writeSigned(outDir, 'manifest-linux.json', manifest, privateKey);
  return manifest;
}

async function packagesCommand(rest) {
  const { values } = parseArgs({
    args: rest,
    strict: true,
    options: {
      version: { type: 'string' },
      'notes-file': { type: 'string' },
      out: { type: 'string' },
      platform: { type: 'string', multiple: true },
      deb: { type: 'string', multiple: true },
      rpm: { type: 'string', multiple: true },
    },
  });
  for (const option of ['version', 'notes-file', 'out', 'platform', 'deb', 'rpm']) {
    if (!values[option]) {
      throw new Error(`${USAGE}\nmissing --${option}`);
    }
  }
  const { platform, deb, rpm } = values;
  if (deb.length !== platform.length || rpm.length !== platform.length) {
    throw new Error(`${USAGE}\neach --platform needs one --deb and one --rpm`);
  }

  const privateKey = privateKeyFromSeed(process.env.ANTIWIRE_UPDATE_SIGNING_KEY);
  const outDir = resolve(values.out);
  await buildPackageManifest({
    version: values.version,
    notes: await readFile(values['notes-file'], 'utf8'),
    packages: platform.flatMap((name, index) => [
      { platform: name, format: 'deb', file: resolve(deb[index]) },
      { platform: name, format: 'rpm', file: resolve(rpm[index]) },
    ]),
    outDir,
    privateKey,
  });
  console.log(`Wrote ${join(outDir, 'manifest-linux.json')} and manifest-linux.json.sig`);
}

async function main(argv) {
  const [command, ...rest] = argv;

  if (command === 'generate-key' && rest.length === 0) {
    const keys = generateKeys();
    console.log(`ANTIWIRE_UPDATE_SIGNING_KEY (secret in the release environment): ${keys.seed}`);
    console.log(`ANTIWIRE_UPDATE_PUBLIC_KEY (variable in the release environment): ${keys.publicKey}`);
    return;
  }

  if (command === 'packages') {
    await packagesCommand(rest);
    return;
  }
  if (command !== 'build') {
    throw new Error(USAGE);
  }
  const { values } = parseArgs({
    args: rest,
    strict: true,
    options: {
      version: { type: 'string' },
      'notes-file': { type: 'string' },
      out: { type: 'string' },
      platform: { type: 'string', multiple: true },
      daemon: { type: 'string', multiple: true },
      client: { type: 'string', multiple: true },
    },
  });
  for (const option of ['version', 'notes-file', 'out', 'platform', 'daemon', 'client']) {
    if (!values[option]) {
      throw new Error(`${USAGE}\nmissing --${option}`);
    }
  }
  const { platform, daemon, client } = values;
  if (daemon.length !== platform.length || client.length !== platform.length) {
    throw new Error(`${USAGE}\neach --platform needs one --daemon and one --client`);
  }

  // Checked before reading any input, so a run without the secret fails at once.
  const privateKey = privateKeyFromSeed(process.env.ANTIWIRE_UPDATE_SIGNING_KEY);
  const outDir = resolve(values.out);
  await buildRelease({
    version: values.version,
    notes: await readFile(values['notes-file'], 'utf8'),
    builds: platform.map((name, index) => ({
      platform: name,
      daemon: resolve(daemon[index]),
      client: resolve(client[index]),
    })),
    outDir,
    privateKey,
  });
  console.log(`Wrote ${join(outDir, 'manifest.json')} and manifest.json.sig`);
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
