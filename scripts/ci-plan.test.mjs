import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AREA_NAMES, changedAreas, plan, runnersFor } from './ci-plan.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PR = runnersFor({ event: 'pull_request' });

const planFor = (files, runners = PR) => plan(changedAreas(files), runners);
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

  test('an eBPF source change builds the objects only', () => {
    const result = planFor([
      'src/antiwire-rs/packages/netmet-rs/crates/netmetrics-linux/ebpf/netmetrics.bpf.c',
    ]);
    expect(result.ebpf).toBe(true);
    expect(result.deny).toBe(false);
    expect(result.matrix.include).toEqual([]);
  });

  test('a firew change runs its suite, the daemon, and the live image', () => {
    const result = planFor(['src/antiwire-rs/packages/firew-rs/crates/firew-linux/src/lib.rs']);
    expect(suites(result)).toContain('firew-rs (ubuntu)');
    expect(suites(result)).toContain('antiwire-rs (ubuntu)');
    expect(result.firewLive).toBe(true);
    expect(result.denyRs).toEqual(['Cargo.toml', 'packages/firew-rs/Cargo.toml']);
  });

  test('a live image change runs the live tests only', () => {
    const result = planFor(['src/antiwire-rs/docker/linux-test-entrypoint.sh']);
    expect(result.firewLive).toBe(true);
    expect(result.deny).toBe(false);
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

  test('only the firew macOS entry runs the live macOS firewall tests', () => {
    const result = planFor(['.github/workflows/ci.yml'], ['ubuntu', 'windows', 'macos']);
    const live = result.matrix.include.filter((entry) => entry.firew_live_macos);
    expect(live.map((entry) => entry.name)).toEqual(['firew-rs (macos)']);
    expect(result.matrix.include).toHaveLength(9);
  });

  test('rust-lld is used on Windows', () => {
    const result = planFor(['.github/workflows/ci.yml'], ['windows']);
    const lld = Object.fromEntries(result.matrix.include.map((entry) => [entry.suite, entry.lld]));
    expect(lld).toEqual({ daemon: true, netmet: true, firew: true });
  });
});
