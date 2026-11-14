import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildPackageManifest,
  buildRelease,
  generateKeys,
  privateKeyFromSeed,
} from './release-manifest.mjs';

/** The raw 32-byte public key wrapped as SPKI DER, the form Node can verify with. */
function publicKeyFromRaw(rawBase64) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(rawBase64, 'base64'),
    ]),
    format: 'der',
    type: 'spki',
  });
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const { seed, publicKey } = generateKeys();

describe('release-manifest', () => {
  let dir;
  let outCount = 0;
  const daemonBytes = Buffer.from('daemon binary bytes');
  const clientBytes = Buffer.from('client binary bytes, a little longer');

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'antiwire-release-'));
    await writeFile(join(dir, 'antiwire-daemon-0.2.0-windows-x86_64.exe'), daemonBytes);
    await writeFile(join(dir, 'antiwire-0.2.0-windows-x86_64.exe'), clientBytes);
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function windowsBuild(platform = 'windows-x86_64') {
    return {
      platform,
      daemon: join(dir, 'antiwire-daemon-0.2.0-windows-x86_64.exe'),
      client: join(dir, 'antiwire-0.2.0-windows-x86_64.exe'),
    };
  }

  function build(overrides = {}) {
    outCount += 1;
    return {
      version: '0.2.0',
      notes: '  Faster blocklist loading.\n',
      builds: [windowsBuild()],
      outDir: join(dir, `out-${outCount}`),
      privateKey: privateKeyFromSeed(seed),
      ...overrides,
    };
  }

  test('generates a 32-byte seed and a 32-byte public key that match', () => {
    expect(Buffer.from(seed, 'base64')).toHaveLength(32);
    expect(Buffer.from(publicKey, 'base64')).toHaveLength(32);

    const bytes = Buffer.from('message');
    const signature = sign(null, bytes, privateKeyFromSeed(seed));
    expect(verify(null, bytes, publicKeyFromRaw(publicKey), signature)).toBe(true);
  });

  test('refuses a missing or malformed signing seed', () => {
    expect(() => privateKeyFromSeed(undefined)).toThrow('not set');
    expect(() => privateKeyFromSeed(Buffer.alloc(31).toString('base64'))).toThrow('32-byte');
  });

  test('writes a manifest in the Rust Manifest shape with a verifiable signature', async () => {
    const options = build();
    const manifest = await buildRelease(options);

    const manifestBytes = await readFile(join(options.outDir, 'manifest.json'));
    const signature = await readFile(join(options.outDir, 'manifest.json.sig'));

    expect(signature).toHaveLength(64);
    expect(verify(null, manifestBytes, publicKeyFromRaw(publicKey), signature)).toBe(true);

    expect(JSON.parse(manifestBytes.toString('utf8'))).toEqual({
      version: '0.2.0',
      notes: 'Faster blocklist loading.',
      files: [
        {
          role: 'daemon',
          platform: 'windows-x86_64',
          name: 'antiwire-daemon-0.2.0-windows-x86_64.exe',
          sha256: sha256(daemonBytes),
          size: daemonBytes.length,
        },
        {
          role: 'client',
          platform: 'windows-x86_64',
          name: 'antiwire-0.2.0-windows-x86_64.exe',
          sha256: sha256(clientBytes),
          size: clientBytes.length,
        },
      ],
    });
    expect(manifest.files[0].sha256).toMatch(/^[0-9a-f]{64}$/u);
  });

  test('refuses an invalid version, platform, empty notes, or oversized notes', async () => {
    await expect(buildRelease(build({ version: 'v0.2.0' }))).rejects.toThrow('semantic version');
    await expect(buildRelease(build({ builds: [windowsBuild('windows')] }))).rejects.toThrow(
      'platform',
    );
    await expect(buildRelease(build({ builds: [] }))).rejects.toThrow('at least one');
    await expect(
      buildRelease(build({ builds: [windowsBuild(), windowsBuild()] })),
    ).rejects.toThrow('listed twice');
    await expect(buildRelease(build({ notes: '   ' }))).rejects.toThrow('empty');
    await expect(buildRelease(build({ notes: 'x'.repeat(2001) }))).rejects.toThrow('2000');
  });

  test('accepts notes of exactly 2000 characters and a prerelease version', async () => {
    const manifest = await buildRelease(
      build({ version: '0.2.0-beta.1', notes: 'x'.repeat(2000) }),
    );
    expect(manifest.version).toBe('0.2.0-beta.1');
    expect(manifest.notes).toHaveLength(2000);
  });

  test('lists every platform in one signed manifest', async () => {
    await writeFile(join(dir, 'antiwire-daemon-0.2.0-macos-aarch64'), daemonBytes);
    await writeFile(join(dir, 'Antiwire-0.2.0-macos-aarch64.app.zip'), clientBytes);
    const manifest = await buildRelease(
      build({
        builds: [
          windowsBuild(),
          {
            platform: 'macos-aarch64',
            daemon: join(dir, 'antiwire-daemon-0.2.0-macos-aarch64'),
            client: join(dir, 'Antiwire-0.2.0-macos-aarch64.app.zip'),
          },
        ],
      }),
    );
    expect(manifest.files.map((file) => `${file.platform}/${file.role}`)).toEqual([
      'windows-x86_64/daemon',
      'windows-x86_64/client',
      'macos-aarch64/daemon',
      'macos-aarch64/client',
    ]);
  });

  describe('packages', () => {
    const debBytes = Buffer.from('deb package bytes');
    const rpmBytes = Buffer.from('rpm package bytes, longer');

    beforeAll(async () => {
      await writeFile(join(dir, 'antiwire_0.2.0_amd64.deb'), debBytes);
      await writeFile(join(dir, 'antiwire-0.2.0-1.x86_64.rpm'), rpmBytes);
    });

    function packages(overrides = {}) {
      outCount += 1;
      return {
        version: '0.2.0',
        notes: ' Linux updates. ',
        packages: [
          { platform: 'linux-x86_64', format: 'deb', file: join(dir, 'antiwire_0.2.0_amd64.deb') },
          {
            platform: 'linux-x86_64',
            format: 'rpm',
            file: join(dir, 'antiwire-0.2.0-1.x86_64.rpm'),
          },
        ],
        outDir: join(dir, `out-${outCount}`),
        privateKey: privateKeyFromSeed(seed),
        ...overrides,
      };
    }

    test('writes manifest-linux.json in the Rust PackageManifest shape, signed', async () => {
      const options = packages();
      await buildPackageManifest(options);

      const bytes = await readFile(join(options.outDir, 'manifest-linux.json'));
      const signature = await readFile(join(options.outDir, 'manifest-linux.json.sig'));
      expect(verify(null, bytes, publicKeyFromRaw(publicKey), signature)).toBe(true);
      expect(JSON.parse(bytes.toString('utf8'))).toEqual({
        version: '0.2.0',
        notes: 'Linux updates.',
        packages: [
          {
            platform: 'linux-x86_64',
            format: 'deb',
            name: 'antiwire_0.2.0_amd64.deb',
            sha256: sha256(debBytes),
            size: debBytes.length,
          },
          {
            platform: 'linux-x86_64',
            format: 'rpm',
            name: 'antiwire-0.2.0-1.x86_64.rpm',
            sha256: sha256(rpmBytes),
            size: rpmBytes.length,
          },
        ],
      });
    });

    test('refuses a non-Linux platform, an unknown format, or a format listed twice', async () => {
      const deb = packages().packages[0];
      await expect(
        buildPackageManifest(packages({ packages: [{ ...deb, platform: 'windows-x86_64' }] })),
      ).rejects.toThrow('linux-x86_64');
      await expect(
        buildPackageManifest(packages({ packages: [{ ...deb, format: 'apk' }] })),
      ).rejects.toThrow('deb or rpm');
      await expect(buildPackageManifest(packages({ packages: [deb, deb] }))).rejects.toThrow(
        'listed twice',
      );
      await expect(buildPackageManifest(packages({ packages: [] }))).rejects.toThrow(
        'at least one',
      );
      await expect(buildPackageManifest(packages({ notes: '' }))).rejects.toThrow('empty');
    });
  });
});
