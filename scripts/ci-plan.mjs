#!/usr/bin/env node
/**
 * Decides which CI jobs .github/workflows/ci.yml runs.
 *
 * Reads the files the event changed, maps them to areas (the daemon workspace, netmet-rs,
 * firew-rs, the client's Rust and Bun code, and so on), and writes the plan to
 * $GITHUB_OUTPUT. A job whose area did not change does not run.
 *
 *   node scripts/ci-plan.mjs                 in GitHub Actions (reads the event from env)
 *   node scripts/ci-plan.mjs --files a b c   print the plan for these changed paths
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RS = 'src/antiwire-rs';
const NETMET = `${RS}/packages/netmet-rs`;
const FIREW = `${RS}/packages/firew-rs`;
const EBPF = `${NETMET}/crates/netmetrics-linux/ebpf`;
const CLIENT = 'src/antiwire-client';

const under = (dir) => (file) => file.startsWith(`${dir}/`);
const oneOf = (...paths) => (file) => paths.includes(file);
const any = (...tests) => (file) => tests.some((test) => test(file));
const isDoc = (file) => file.endsWith('.md');

/** A change to either of these files can change any job, so it runs every area. */
const CI_FILES = ['.github/workflows/ci.yml', 'scripts/ci-plan.mjs'];

/**
 * Paths that start each area. Markdown never reaches a compiler or a test, so it starts
 * nothing. Each nested workspace's own .github and docs directories are not used here.
 */
const AREAS = {
  daemon: any(
    under(`${RS}/crates`),
    oneOf(
      `${RS}/Cargo.toml`,
      `${RS}/Cargo.lock`,
      `${RS}/scripts/ci-linux-offline.sh`,
      `${RS}/scripts/ci-windows-os.sh`,
      `${RS}/scripts/ci-macos-os.sh`,
    ),
  ),
  netmet: (file) =>
    under(NETMET)(file) &&
    !under(EBPF)(file) &&
    !under(`${NETMET}/.github`)(file) &&
    !under(`${NETMET}/docs`)(file),
  ebpf: under(EBPF),
  firew: (file) =>
    under(FIREW)(file) && !under(`${FIREW}/.github`)(file) && !under(`${FIREW}/docs`)(file),
  // The privileged Linux image. Its live mode runs firew-rs tests only.
  firewLive: oneOf(
    `${RS}/docker/linux-test.Dockerfile`,
    `${RS}/docker/linux-test-entrypoint.sh`,
    `${RS}/.dockerignore`,
    `${RS}/scripts/ci-linux-live.sh`,
  ),
  // The Electron client: renderer, main process, and the proto its gRPC client loads.
  bun: any(
    (file) => under(CLIENT)(file) && !isDoc(file),
    under(`${RS}/crates/antiwire-proto/proto`),
    // The Bun every workflow installs; a new one has to pass the client checks.
    oneOf('.bun-version'),
  ),
  // The product version is written in these three places (see scripts/check-versions.mjs),
  // and these scripts have tests the scripts job runs.
  scripts: oneOf(
    '.bun-version',
    `${CLIENT}/package.json`,
    `${RS}/Cargo.toml`,
    '.github/workflows/packages.yml',
    'scripts/check-versions.mjs',
    'scripts/check-versions.test.mjs',
    'scripts/release-manifest.mjs',
    'scripts/release-manifest.test.mjs',
    'scripts/release-channel.mjs',
    'scripts/release-channel.test.mjs',
    'scripts/set-version.mjs',
    'scripts/set-version.test.mjs',
    'scripts/repository.mjs',
    'scripts/repository.test.mjs',
    'scripts/ci-plan.test.mjs',
  ),
  denyRs: oneOf(`${RS}/deny.toml`),
};

export const AREA_NAMES = Object.keys(AREAS);

/** The set of areas the changed files touch. */
export function changedAreas(files) {
  const areas = new Set();
  for (const file of files) {
    if (CI_FILES.includes(file)) {
      return new Set(AREA_NAMES);
    }
    if (isDoc(file)) {
      continue;
    }
    for (const [name, matches] of Object.entries(AREAS)) {
      if (matches(file)) {
        areas.add(name);
      }
    }
  }
  return areas;
}

const NIGHTLY = '0 3 * * *';
const WEEKLY = '0 4 * * 0';

/**
 * The runners an event uses. macOS costs 10x Linux and Windows 2x, so pull requests skip
 * macOS and pushes to main run Linux only. The weekly run publishes the Windows caches
 * pull requests restore, and the nightly run covers macOS.
 */
export function runnersFor({ event, schedule, os }) {
  if (event === 'pull_request') return ['ubuntu', 'windows'];
  if (event === 'push') return ['ubuntu'];
  if (event === 'schedule') {
    if (schedule === NIGHTLY) return ['macos'];
    if (schedule === WEEKLY) return ['windows'];
    throw new Error(`unknown schedule: ${schedule}`);
  }
  if (!os || os === 'all') return ['ubuntu', 'windows', 'macos'];
  if (['ubuntu', 'windows', 'macos'].includes(os)) return [os];
  throw new Error(`unknown os input: ${os}`);
}

/** How far back a scheduled run looks for changes on main. */
export function scheduleWindow(schedule) {
  return schedule === WEEKLY ? '8 days ago' : '25 hours ago';
}

const APT = {
  daemon:
    'iptables nftables iproute2 libpcap-dev clang llvm libbpf-dev libcap2-bin pkg-config',
  netmet: 'libpcap-dev clang llvm libbpf-dev libcap2-bin pkg-config',
  firew: 'iptables nftables iproute2 pkg-config',
};

const nested = (manifest) =>
  `cargo test --manifest-path ${manifest} --workspace --all-features`;

/** One entry per Rust test suite, before the runner is chosen. */
const SUITES = {
  daemon: {
    name: 'antiwire-rs',
    dir: RS,
    cache: { workspace: RS, key: 'antiwire-rs-debug' },
    run: {
      ubuntu: 'bash ./scripts/ci-linux-offline.sh',
      windows: 'bash ./scripts/ci-windows-os.sh',
      macos: 'bash ./scripts/ci-macos-os.sh',
    },
    apt: APT.daemon,
    brew: 'libpcap',
    lld: true,
    timeout: { ubuntu: 20, windows: 30, macos: 25 },
  },
  netmet: {
    name: 'netmet-rs',
    dir: RS,
    cache: { workspace: NETMET, key: 'netmet-rs-debug' },
    run: nested('packages/netmet-rs/Cargo.toml'),
    apt: APT.netmet,
    brew: 'libpcap',
    lld: true,
    timeout: { ubuntu: 20, windows: 30, macos: 25 },
  },
  firew: {
    name: 'firew-rs',
    dir: RS,
    cache: { workspace: FIREW, key: 'firew-rs-debug' },
    run: nested('packages/firew-rs/Cargo.toml'),
    apt: APT.firew,
    brew: '',
    lld: true,
    timeout: { ubuntu: 20, windows: 30, macos: 25 },
  },
};

/**
 * The areas each Rust suite tests. The daemon depends on netmet-rs and firew-rs by path, so
 * a change to either also builds and tests the daemon against it.
 */
const SUITE_AREAS = {
  daemon: ['daemon', 'netmet', 'firew'],
  netmet: ['netmet'],
  firew: ['firew'],
};

/** The workflow's plan for these changed areas on these runners. */
export function plan(areas, runners) {
  const has = (...names) => names.some((name) => areas.has(name));
  const linux = runners.includes('ubuntu');

  const include = [];
  for (const [suite, config] of Object.entries(SUITES)) {
    if (!has(...SUITE_AREAS[suite])) continue;
    for (const runner of runners) {
      include.push({
        name: `${config.name} (${runner})`,
        suite,
        runner: `${runner}-latest`,
        dir: config.dir,
        run: typeof config.run === 'string' ? config.run : config.run[runner],
        cache_workspace: config.cache.workspace,
        cache_key: config.cache.key,
        apt: runner === 'ubuntu' ? config.apt : '',
        brew: runner === 'macos' ? config.brew : '',
        lld: runner === 'windows' && config.lld,
        firew_live_macos: suite === 'firew' && runner === 'macos',
        timeout: config.timeout[runner],
      });
    }
  }

  // Manifests under src/antiwire-rs checked against its deny.toml. The daemon's graph holds
  // the netmet and firew crates it uses; their own workspaces add their dev-dependencies.
  // A deny.toml change rechecks all three.
  const denyRs = [];
  if (has('daemon', 'netmet', 'firew', 'denyRs')) denyRs.push('Cargo.toml');
  if (has('netmet', 'denyRs')) denyRs.push('packages/netmet-rs/Cargo.toml');
  if (has('firew', 'denyRs')) denyRs.push('packages/firew-rs/Cargo.toml');

  return {
    matrix: { include },
    denyRs,
    deny: denyRs.length > 0,
    bun: linux && has('bun'),
    scripts: linux && has('scripts'),
    ebpf: linux && has('ebpf'),
    firewLive: linux && has('firew', 'firewLive'),
  };
}

const git = (...args) =>
  execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

const lines = (text) => text.split('\n').filter(Boolean);

const exists = (rev) => {
  try {
    git('cat-file', '-e', `${rev}^{commit}`);
    return true;
  } catch {
    return false;
  }
};

/**
 * The files this event changed, or null when every area should run (a dispatch with
 * scope=all, or history that cannot be compared). Needs a full clone, except on pull
 * requests, whose merge commit only needs its first parent.
 */
export function changedFiles(env) {
  const event = env.EVENT_NAME;
  // --no-renames lists both sides of a move, so moving a file out of an area still runs it.
  const diff = (base) => lines(git('diff', '--name-only', '--no-renames', base, 'HEAD'));

  if (event === 'pull_request') {
    // actions/checkout checks out the merge commit; its first parent is the base branch.
    return diff('HEAD^1');
  }
  if (event === 'push') {
    const before = env.BEFORE ?? '';
    if (/^0*$/u.test(before) || !exists(before)) return null;
    return diff(before);
  }
  if (event === 'schedule') {
    const base = git('rev-list', '-1', '--first-parent', `--before=${scheduleWindow(env.SCHEDULE)}`, 'HEAD');
    return base ? diff(base) : null;
  }
  // workflow_dispatch, including packages.yml calling this workflow.
  if (env.SCOPE !== 'changed') return null;
  const base = git('merge-base', 'origin/main', 'HEAD');
  return diff(base);
}

function main(argv) {
  const filesFlag = argv.indexOf('--files');
  const env = process.env;
  const files = filesFlag >= 0 ? argv.slice(filesFlag + 1) : changedFiles(env);
  const areas = files === null ? new Set(AREA_NAMES) : changedAreas(files);
  const runners =
    filesFlag >= 0
      ? runnersFor({ event: 'pull_request' })
      : runnersFor({ event: env.EVENT_NAME, schedule: env.SCHEDULE, os: env.OS });
  const result = plan(areas, runners);

  const summary = [
    `Changed files: ${files === null ? 'all (every area runs)' : files.length}`,
    `Areas: ${[...areas].join(', ') || 'none'}`,
    `Runners: ${runners.join(', ')}`,
    `cargo deny: ${result.denyRs.join(', ') || 'skipped'}`,
    `Rust suites: ${result.matrix.include.map((entry) => entry.name).join(', ') || 'none'}`,
    `Other jobs: ${['bun', 'scripts', 'ebpf', 'firewLive'].filter((job) => result[job]).join(', ') || 'none'}`,
  ];
  console.log(summary.join('\n'));

  if (env.GITHUB_OUTPUT) {
    const outputs = {
      matrix: JSON.stringify(result.matrix),
      has_matrix: result.matrix.include.length > 0,
      deny: result.deny,
      deny_rs: result.denyRs.join(' '),
      bun: result.bun,
      scripts: result.scripts,
      ebpf: result.ebpf,
      firew_live: result.firewLive,
    };
    appendFileSync(
      env.GITHUB_OUTPUT,
      Object.entries(outputs)
        .map(([key, value]) => `${key}=${value}\n`)
        .join(''),
    );
  }
  if (env.GITHUB_STEP_SUMMARY) {
    appendFileSync(env.GITHUB_STEP_SUMMARY, `### CI plan\n\n${summary.map((line) => `- ${line}`).join('\n')}\n`);
  }
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main(process.argv.slice(2));
}
