# Antiwire Client (Electron + React)

Desktop client for the Antiwire daemon, built with Electron, React 19, TypeScript, Radix UI,
and Lucide icons.

## Prerequisites

- [Bun](https://bun.sh/)
- Running `antiwire-daemon` (Windows: TLS on `127.0.0.1:50051`)

## Development

```bash
cd src/antiwire-client
bun install
bun run dev
```

## Scripts

| Command | Description |
|---------|-------------|
| `bun run dev` | Electron app with the Vite dev server (hot reload) |
| `bun run dev:web` | Browser-only preview with synthetic data on port 1420 |
| `bun run check` | Typecheck (renderer and main process) and lint |
| `bun run test` | Unit tests (`bun test`) |
| `bun run build` | Production bundles in `out/` |
| `bun run package:dir` | Unpacked app in `dist/`, which the installers package |
| `bun run package` | Platform installers via electron-builder |

## Architecture

| Path | Role |
|------|------|
| `electron/main` | Main process: gRPC client to `antiwire-daemon` (`@grpc/grpc-js`, loading `antiwire-proto/proto/antiwire.proto` at runtime), IPC router, native dialogs, tray, notifications, packet inspector window |
| `electron/preload` | Exposes only `window.antiwire.invoke` / `on` to the renderer |
| `shared/ipc.ts` | The single list of commands and events, shared by both sides |
| `src` | React renderer: routes, stores (`src/lib/stores`), components, design tokens (`src/app.css`) |

### Security

- The renderer runs sandboxed with context isolation and no Node integration, served from
  the custom `app://antiwire` origin with a strict Content Security Policy.
- Navigation, new windows, webviews, downloads and permission prompts are refused; every
  network request that is not an app resource is cancelled. The renderer talks to the daemon
  only through the main process.
- Each IPC call is checked for its sender (top frame of an app window), the window's role
  (the packet inspector gets a smaller command set), and arguments (strict zod schemas).
- The IPC token never leaves the main process.
- File writes accept only a path the native save dialog just returned, once.
- Packaged builds flip Electron fuses (`scripts/after-pack.mjs`): no `ELECTRON_RUN_AS_NODE`,
  no `NODE_OPTIONS`, no inspector flags, ASAR integrity checking, and only loading the app
  from the ASAR.

### Performance

- Pages are lazy-loaded; long lists are virtualized.
- Traffic and capture stream events are batched in the main process (every 100 ms, bounded)
  before crossing IPC.
- Store subscriptions select the narrowest slice, so the per-second daemon refresh only
  re-renders what changed.
- Charts are hand-written SVG; there is no charting library.

## Window appearance

The main window and packet inspector use transparent, frameless windows. The shared document
clips both the shell and body-portaled overlays to `--window-radius` (8px) in `src/app.css`,
including when resized. Linux requires a compositor that supports transparent windows.

## IPC

The client reads `ipc.token` and `ipc.crt` from standard Antiwire data directories and connects
to the daemon gRPC API with the `x-antiwire-token` header.

A release daemon makes `ipc.token` readable only by administrators and one local group:
`Antiwire Users` on Windows, `antiwire` on Linux and macOS. On Linux and macOS the IPC
socket is restricted to the same group. The installers create the group and add the
installing account, and membership applies from the next sign-in. The daemon writes a
new token every time it starts. An account outside the group gets an error telling it
which group to join. Debug builds keep the token under the developer's own profile and
skip these restrictions.

## Browser preview for UI development and agents

Run `bun run dev:web` and open `http://localhost:1420`. Browser sessions load synthetic data
automatically; no daemon, IPC credentials, or Administrator permissions are required for these
browser-only checks. Native firewall, DNS, and traffic accounting tests still require the
elevated desktop workflow.

The **Browser preview** banner identifies synthetic data on every page. It offers
**Reset sample data** (a full reload) and **Test offline** (`?preview=offline`).
The selected scenario survives client-side navigation; a fresh document without
that parameter defaults to sample data. Initial onboarding is skipped in previews;
the existing Setup button can still open it.

The sample backend provides six apps, 96 connection records, rules, alerts,
seven days of activity, populated throughput charts, settings, and five network
devices. Filtering, sorting, pagination, rule edits, alert dismissal, daemon
settings changes, scans, and device watches operate on in-memory state. Reloading
resets those sample changes. Existing browser appearance/language preferences
still persist normally.

On Capture, press **Start capture** to generate synthetic packets, then click a
packet to open the browser inspector. `/inspector` also works directly with a
sample packet. Native exports, file dialogs, and window management remain desktop
features; unsupported sample commands report an explicit preview error. Fixtures
exercise GUI behavior only and never prove native enforcement or live accounting.

Preview mode is gated by Vite's development flag and the absence of the Electron bridge.
Production builds and the desktop app always use the real API. Fixture data uses example
domains and documentation IP ranges, with no real account, host, or credential data.

Fixtures and their in-memory backend live in `src/lib/preview/`. Add new mock
commands there when a GUI feature introduces a new daemon endpoint; unimplemented
commands deliberately fail instead of silently pretending to succeed.
