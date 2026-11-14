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
  ebpf: any(under(EBPF), oneOf(`${RS}/scripts/ci-install-ebpf-deps.sh`)),
  firew: (file) =>
    under(FIREW)(file) && !under(`${FIREW}/.github`)(file) && !under(`${FIREW}/docs`)(file),
  // What runs the elevated tests: the privileged Linux image, whose live mode runs the
  // firew-rs tests, and the Windows and Unix elevated scripts. Only an elevated dispatch
  // uses them, so in any other run this area starts nothing.
  elevated: oneOf(
    `${RS}/docker/linux-test.Dockerfile`,
    `${RS}/docker/linux-test-entrypoint.sh`,
    `${RS}/.dockerignore`,
    `${RS}/scripts/ci-linux-live.sh`,
    `${RS}/docker/windows-test-entrypoint.ps1`,
    `${RS}/scripts/ci-elevated-unix.sh`,
    `${RS}/scripts/ci-install-ebpf-deps.sh`,
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

/** The native ARM64 legs. Only a dispatch that names one runs it, and it saves no caches. */
const HAND_RUN = ['windows-arm', 'linux-arm'];

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
  // `all` leaves out the native ARM64 legs: each runs only when asked for by name.
  if (!os || os === 'all') return ['ubuntu', 'windows', 'macos'];
  if (['ubuntu', 'windows', 'macos', ...HAND_RUN].includes(os)) return [os];
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

// `cargo check`, not clippy: the toolchain is installed with the minimal profile.
const WINDOWS_ARM64_CHECK =
  'rustup target add aarch64-pc-windows-msvc && RUSTFLAGS="-D warnings" ' +
  'cargo check --manifest-path packages/netmet-rs/Cargo.toml -p netmetrics-windows -p netmetrics ' +
  '--all-features --all-targets --target aarch64-pc-windows-msvc';

const windowsElevated = (mode) =>
  `pwsh -NoProfile -File ./docker/windows-test-entrypoint.ps1 -Mode ${mode}`;

/**
 * The elevated tests of a suite on each runner, and nothing else. Windows reuses the Windows
 * test image's entrypoint; Linux and macOS run scripts/ci-elevated-unix.sh as root.
 */
const elevated = (suite, windows, unixRunners = ['ubuntu', 'macos']) => ({
  ...Object.fromEntries(
    unixRunners.map((runner) => [runner, `bash ./scripts/ci-elevated-unix.sh ${suite}`]),
  ),
  windows,
  'windows-arm': windows,
});

/**
 * The `runs-on` label for each runner name: a Blacksmith machine, of which six cores is the
 * smallest macOS one. `windows-arm` is GitHub's hosted ARM64 Windows image, because
 * Blacksmith has no ARM64 Windows machine; it runs the ARM64 build natively, where WinDivert
 * is compiled out. `linux-arm` is the same kind of machine the ARM64 Linux release is built on.
 */
export const RUNNER_LABELS = {
  ubuntu: 'blacksmith-4vcpu-ubuntu-2404',
  windows: 'blacksmith-4vcpu-windows-2025',
  macos: 'blacksmith-6vcpu-macos-latest',
  'windows-arm': 'windows-11-arm',
  'linux-arm': 'blacksmith-4vcpu-ubuntu-2404-arm',
};

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
      'windows-arm': 'bash ./scripts/ci-windows-os.sh',
      'linux-arm': 'bash ./scripts/ci-linux-offline.sh',
    },
    elevated: elevated('daemon', windowsElevated('live-daemon')),
    apt: APT.daemon,
    brew: 'libpcap',
    lld: true,
    // The hand-run ARM64 legs have no warm cache, and native ARM64 Windows builds are slower.
    timeout: { ubuntu: 20, windows: 30, macos: 25, 'windows-arm': 60, 'linux-arm': 30 },
  },
  netmet: {
    name: 'netmet-rs',
    dir: RS,
    cache: { workspace: NETMET, key: 'netmet-rs-debug' },
    run: {
      ubuntu: nested('packages/netmet-rs/Cargo.toml'),
      // The ARM64 Windows build compiles WinDivert out; check it still builds. No runner
      // is ARM64 Windows, so this checks rather than tests.
      windows: `${nested('packages/netmet-rs/Cargo.toml')} && ${WINDOWS_ARM64_CHECK}`,
      macos: nested('packages/netmet-rs/Cargo.toml'),
      'windows-arm': nested('packages/netmet-rs/Cargo.toml'),
      'linux-arm': nested('packages/netmet-rs/Cargo.toml'),
    },
    // The container cannot load WinDivert, so its tests run here rather than in the entrypoint.
    // On ARM64 they are compiled out. The package download test only needs the network.
    elevated: elevated(
      'netmet',
      `${windowsElevated('live-netmet')} && ` +
        'cargo test --manifest-path packages/netmet-rs/Cargo.toml -p netmetrics-windows --lib -- ' +
        '--ignored --test-threads=1 --nocapture --skip official_download_matches_the_pinned_hashes',
    ),
    apt: APT.netmet,
    brew: 'libpcap',
    lld: true,
    timeout: { ubuntu: 20, windows: 30, macos: 25, 'windows-arm': 45, 'linux-arm': 30 },
  },
  firew: {
    name: 'firew-rs',
    dir: RS,
    cache: { workspace: FIREW, key: 'firew-rs-debug' },
    run: nested('packages/firew-rs/Cargo.toml'),
    // On Linux they run in the privileged image instead (the firew-live job).
    elevated: elevated('firew', windowsElevated('live-firew'), ['macos']),
    apt: APT.firew,
    brew: '',
    lld: true,
    timeout: { ubuntu: 20, windows: 30, macos: 25, 'windows-arm': 45, 'linux-arm': 30 },
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

/**
 * The workflow's plan for these changed areas on these runners. With `elevated`, set only by
 * a dispatch, it runs the elevated tests and nothing else; no other run includes them.
 */
export function plan(areas, runners, { elevated: onlyElevated = false } = {}) {
  const has = (...names) => names.some((name) => areas.has(name));
  const linux = runners.includes('ubuntu');

  const include = [];
  for (const [suite, config] of Object.entries(SUITES)) {
    if (!has(...SUITE_AREAS[suite], ...(onlyElevated ? ['elevated'] : []))) continue;
    for (const runner of runners) {
      const runs = onlyElevated ? config.elevated : config.run;
      const run = typeof runs === 'string' ? runs : runs[runner];
      if (!run) continue;
      include.push({
        name: `${config.name}${onlyElevated ? ' elevated' : ''} (${runner})`,
        suite,
        runner: RUNNER_LABELS[runner],
        dir: config.dir,
        run,
        cache_workspace: config.cache.workspace,
        cache_key: config.cache.key,
        apt: runner === 'ubuntu' || runner === 'linux-arm' ? config.apt : '',
        brew: runner === 'macos' ? config.brew : '',
        // The linker override names the x86_64 target, so it is for the x64 leg only.
        lld: runner === 'windows' && config.lld,
        windows_arm: runner === 'windows-arm',
        // A run only made by hand saves no caches; its archives would take space from main's.
        publish: !onlyElevated && !HAND_RUN.includes(runner),
        timeout: config.timeout[runner],
      });
    }
  }

  // Manifests under src/antiwire-rs checked against its deny.toml. The daemon's graph holds
  // the netmet and firew crates it uses; their own workspaces add their dev-dependencies.
  // A deny.toml change rechecks all three. An elevated run tests a branch the pull request
  // checks already gate, so it runs its tests only.
  const denyRs = [];
  if (onlyElevated) {
    return {
      matrix: { include },
      denyRs,
      deny: false,
      bun: false,
      scripts: false,
      ebpf: false,
      firewLive: linux && has('firew', 'elevated'),
    };
  }
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
    firewLive: false,
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
  const elevated = filesFlag < 0 && env.ELEVATED === 'true';
  const result = plan(areas, runners, { elevated });

  const summary = [
    `Changed files: ${files === null ? 'all (every area runs)' : files.length}`,
    `Areas: ${[...areas].join(', ') || 'none'}`,
    `Runners: ${runners.join(', ')}`,
    `Tests: ${elevated ? 'elevated only' : 'unprivileged'}`,
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
