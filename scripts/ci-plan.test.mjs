import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AREA_NAMES, changedAreas, plan, runnersFor } from './ci-plan.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PR = runnersFor({ event: 'pull_request' });

const planFor = (files, runners = PR, options) => plan(changedAreas(files), runners, options);
const suites = (result) => result.matrix.include.map((entry) => entry.name);

describe('ci-plan areas', () => {
  test('docs start nothing', () => {
    const result = planFor(['src/antiwire-rs/crates/antiwire-flow/README.md', 'AGENTS.md']);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
    expect(result.bun || result.scripts || result.ebpf || result.firewLive).toBe(false);
  });

  test('a daemon change runs the daemon only', () => {
    const result = planFor(['src/antiwire-rs/crates/antiwire-flow/src/lib.rs']);
    expect(suites(result)).toEqual(['antiwire-rs (ubuntu)', 'antiwire-rs (windows)']);
    expect(result.denyRs).toEqual(['Cargo.toml']);
    expect(result.firewLive).toBe(false);
  });

  test('a netmet change also builds the daemon that depends on it', () => {
    const result = planFor(['src/antiwire-rs/packages/netmet-rs/crates/netmetrics/src/lib.rs']);
    expect(suites(result)).toEqual([
      'antiwire-rs (ubuntu)',
      'antiwire-rs (windows)',
      'netmet-rs (ubuntu)',
      'netmet-rs (windows)',
    ]);
    expect(result.denyRs).toEqual(['Cargo.toml', 'packages/netmet-rs/Cargo.toml']);
    expect(result.ebpf).toBe(false);
  });

  test('only the Windows netmet leg also checks the ARM64 build without WinDivert', () => {
    const result = planFor(['src/antiwire-rs/packages/netmet-rs/crates/netmetrics/src/lib.rs']);
    const run = (name) => result.matrix.include.find((entry) => entry.name === name).run;
    expect(run('netmet-rs (windows)')).toContain('--target aarch64-pc-windows-msvc');
    expect(run('netmet-rs (ubuntu)')).not.toContain('aarch64');
  });

  test('the ARM64 Windows leg runs natively, by name only, and saves no caches', () => {
    expect(runnersFor({ event: 'workflow_dispatch', os: 'all' })).not.toContain('windows-arm');
    const result = planFor(
      ['src/antiwire-rs/packages/netmet-rs/crates/netmetrics/src/lib.rs'],
      ['windows-arm'],
    );
    expect(suites(result)).toEqual(['antiwire-rs (windows-arm)', 'netmet-rs (windows-arm)']);
    for (const entry of result.matrix.include) {
      expect(entry.runner).toBe('windows-11-arm');
      expect(entry.windows_arm).toBe(true);
      expect(entry.publish).toBe(false);
      expect(entry.lld).toBe(false);
      expect(entry.run).not.toContain('--target');
      expect(entry.timeout).toBeGreaterThan(0);
    }
    expect(result.bun || result.scripts || result.ebpf || result.firewLive).toBe(false);
  });

  test('an eBPF source change builds the objects only', () => {
    const result = planFor([
      'src/antiwire-rs/packages/netmet-rs/crates/netmetrics-linux/ebpf/netmetrics.bpf.c',
    ]);
    expect(result.ebpf).toBe(true);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });

  test('a firew change runs its suite and the daemon, and no elevated tests', () => {
    const result = planFor(['src/antiwire-rs/packages/firew-rs/crates/firew-linux/src/lib.rs']);
    expect(suites(result)).toContain('firew-rs (ubuntu)');
    expect(suites(result)).toContain('antiwire-rs (ubuntu)');
    expect(result.firewLive).toBe(false);
    expect(result.denyRs).toEqual(['Cargo.toml', 'packages/firew-rs/Cargo.toml']);
  });

  test('a change to what runs the elevated tests starts nothing outside an elevated run', () => {
    const result = planFor([
      'src/antiwire-rs/docker/linux-test-entrypoint.sh',
      'src/antiwire-rs/docker/windows-test-entrypoint.ps1',
      'src/antiwire-rs/scripts/ci-elevated-unix.sh',
    ]);
    expect(result.firewLive).toBe(false);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });

  test('the eBPF dependency script builds the objects', () => {
    const result = planFor(['src/antiwire-rs/scripts/ci-install-ebpf-deps.sh']);
    expect(result.ebpf).toBe(true);
    expect(result.matrix.include).toEqual([]);
  });

  test('a frontend dependency edit runs Bun and the version check, not Rust', () => {
    const result = planFor(['src/antiwire-client/package.json']);
    expect(result.bun).toBe(true);
    expect(result.scripts).toBe(true);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });

  test('a Bun upgrade runs the client and script tests, not Rust', () => {
    const result = planFor(['.bun-version']);
    expect(result.bun).toBe(true);
    expect(result.scripts).toBe(true);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });

  test('an Electron main-process change runs Bun, not Rust', () => {
    const result = planFor(['src/antiwire-client/electron/main/index.ts']);
    expect(result.bun).toBe(true);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });

  test('antiwire-proto is shared by the daemon and the client', () => {
    const result = planFor(['src/antiwire-rs/crates/antiwire-proto/proto/antiwire.proto']);
    expect(suites(result)).toContain('antiwire-rs (ubuntu)');
    expect(result.bun).toBe(true);
  });

  test('a deny.toml change runs cargo deny only', () => {
    const rs = planFor(['src/antiwire-rs/deny.toml']);
    expect(rs.denyRs).toEqual([
      'Cargo.toml',
      'packages/netmet-rs/Cargo.toml',
      'packages/firew-rs/Cargo.toml',
    ]);
    expect(rs.matrix.include).toEqual([]);
  });

  test('a CI change runs every area', () => {
    expect(changedAreas(['.github/workflows/ci.yml'])).toEqual(new Set(AREA_NAMES));
    expect(changedAreas(['scripts/ci-plan.mjs'])).toEqual(new Set(AREA_NAMES));
  });

  test("a nested workspace's own docs and CI files start nothing", () => {
    const result = planFor([
      'src/antiwire-rs/packages/netmet-rs/.github/workflows/ci.yml',
      'src/antiwire-rs/packages/firew-rs/docs/design.txt',
    ]);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });
});

describe('ci-plan elevated runs', () => {
  const ALL = ['ubuntu', 'windows', 'macos'];
  const elevatedFor = (files, runners = ALL) => planFor(files, runners, { elevated: true });

  test('run the elevated tests and nothing else', () => {
    const result = elevatedFor(['.github/workflows/ci.yml']);
    expect(suites(result)).toEqual([
      'antiwire-rs elevated (ubuntu)',
      'antiwire-rs elevated (windows)',
      'antiwire-rs elevated (macos)',
      'netmet-rs elevated (ubuntu)',
      'netmet-rs elevated (windows)',
      'netmet-rs elevated (macos)',
      'firew-rs elevated (windows)',
      'firew-rs elevated (macos)',
    ]);
    expect(result.firewLive).toBe(true);
    expect(result.deny || result.bun || result.scripts || result.ebpf).toBe(false);
    for (const entry of result.matrix.include) {
      expect(entry.publish).toBe(false);
      expect(entry.run).toMatch(/windows-test-entrypoint\.ps1 -Mode live-|ci-elevated-unix\.sh /u);
      expect(entry.run).not.toContain('--workspace');
    }
  });

  test('each runner runs its own elevated script', () => {
    const result = elevatedFor(['.github/workflows/ci.yml'], [...ALL, 'windows-arm']);
    const run = (name) => result.matrix.include.find((entry) => entry.name === name).run;
    expect(run('antiwire-rs elevated (ubuntu)')).toBe('bash ./scripts/ci-elevated-unix.sh daemon');
    expect(run('firew-rs elevated (macos)')).toBe('bash ./scripts/ci-elevated-unix.sh firew');
    expect(run('antiwire-rs elevated (windows-arm)')).toContain('-Mode live-daemon');
    expect(run('netmet-rs elevated (windows)')).toContain('-p netmetrics-windows --lib');
    expect(run('netmet-rs elevated (windows)')).toContain('--skip official_download');
  });

  test('follow the changed areas', () => {
    const daemon = elevatedFor(['src/antiwire-rs/crates/antiwire-flow/src/lib.rs']);
    expect(suites(daemon)).toEqual([
      'antiwire-rs elevated (ubuntu)',
      'antiwire-rs elevated (windows)',
      'antiwire-rs elevated (macos)',
    ]);
    expect(daemon.firewLive).toBe(false);
    const scripts = elevatedFor(['src/antiwire-rs/docker/windows-test-entrypoint.ps1']);
    expect(scripts.matrix.include).toHaveLength(8);
    expect(scripts.firewLive).toBe(true);
    expect(elevatedFor(['src/antiwire-client/package.json']).matrix.include).toEqual([]);
  });
});

describe('ci-plan ARM64 Linux', () => {
  test('the leg runs the Linux suites natively, by name only, and saves no caches', () => {
    expect(runnersFor({ event: 'workflow_dispatch', os: 'all' })).not.toContain('linux-arm');
    expect(runnersFor({ event: 'workflow_dispatch', os: 'linux-arm' })).toEqual(['linux-arm']);
    const ubuntu = planFor(['.github/workflows/ci.yml'], ['ubuntu']);
    const result = planFor(['.github/workflows/ci.yml'], ['linux-arm']);
    expect(suites(result)).toEqual([
      'antiwire-rs (linux-arm)',
      'netmet-rs (linux-arm)',
      'firew-rs (linux-arm)',
    ]);
    result.matrix.include.forEach((entry, index) => {
      expect(entry.runner).toBe('blacksmith-4vcpu-ubuntu-2404-arm');
      expect(entry.run).toBe(ubuntu.matrix.include[index].run);
      expect(entry.apt).toBe(ubuntu.matrix.include[index].apt);
      expect(entry.publish).toBe(false);
      expect(entry.timeout).toBeGreaterThan(0);
    });
    expect(result.bun || result.scripts || result.ebpf || result.firewLive).toBe(false);
  });
});

describe('ci-plan runners', () => {
  test('each event uses its runners', () => {
    expect(runnersFor({ event: 'pull_request' })).toEqual(['ubuntu', 'windows']);
    expect(runnersFor({ event: 'push' })).toEqual(['ubuntu']);
    expect(runnersFor({ event: 'schedule', schedule: '0 3 * * *' })).toEqual(['macos']);
    expect(runnersFor({ event: 'schedule', schedule: '0 4 * * 0' })).toEqual(['windows']);
    expect(runnersFor({ event: 'workflow_dispatch', os: 'all' })).toEqual([
      'ubuntu',
      'windows',
      'macos',
    ]);
    expect(runnersFor({ event: 'workflow_dispatch', os: 'macos' })).toEqual(['macos']);
    expect(runnersFor({ event: 'workflow_dispatch', os: 'windows-arm' })).toEqual([
      'windows-arm',
    ]);
  });

  test('every suite gets a machine label for each runner', () => {
    const entries = planFor(['.github/workflows/ci.yml'], ['ubuntu', 'windows', 'macos']).matrix
      .include;
    expect(new Set(entries.map((entry) => entry.runner))).toEqual(
      new Set([
        'blacksmith-4vcpu-ubuntu-2404',
        'blacksmith-4vcpu-windows-2025',
        'blacksmith-6vcpu-macos-latest',
      ]),
    );
  });

  test('the workflow crons match the planner', () => {
    const workflow = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8');
    const crons = [...workflow.matchAll(/cron: "([^"]+)"/gu)].map((match) => match[1]);
    expect(crons.sort()).toEqual(['0 3 * * *', '0 4 * * 0']);
    for (const schedule of crons) {
      expect(() => runnersFor({ event: 'schedule', schedule })).not.toThrow();
    }
  });

  test('Linux-only jobs do not run on a macOS or Windows schedule', () => {
    const files = [
      'src/antiwire-client/package.json',
      'src/antiwire-rs/packages/firew-rs/crates/firew-linux/src/lib.rs',
      'src/antiwire-rs/packages/netmet-rs/crates/netmetrics-linux/ebpf/netmetrics.bpf.c',
    ];
    const result = planFor(files, ['macos']);
    expect(result.bun || result.scripts || result.ebpf || result.firewLive).toBe(false);
    expect(suites(result)).toContain('firew-rs (macos)');
  });

  test('no scheduled or pull request run includes an elevated test', () => {
    const files = ['.github/workflows/ci.yml'];
    const events = [PR, ['ubuntu'], ['macos'], ['windows'], ['ubuntu', 'windows', 'macos']];
    for (const runners of events) {
      const result = planFor(files, runners);
      expect(result.firewLive).toBe(false);
      for (const entry of result.matrix.include) {
        expect(entry.run).not.toMatch(/--ignored|elevated|-Mode live/u);
      }
    }
  });

  test('rust-lld is used on Windows', () => {
    const result = planFor(['.github/workflows/ci.yml'], ['windows']);
    const lld = Object.fromEntries(result.matrix.include.map((entry) => [entry.suite, entry.lld]));
    expect(lld).toEqual({ daemon: true, netmet: true, firew: true });
  });
});
