# antiwire-client

The desktop client: an Electron app with a React renderer. Project-wide rules, CI and releases
are in the [root guide](../../AGENTS.md). `README.md` here covers the security model, window
appearance and the browser preview in more depth.

## Commands

This package uses `bun`, not `npm`. Bun is pinned in `.bun-version` at the repository root, and
every workflow installs that version; `bun check` and `bun fmt` need 1.4 or newer.

```bash
bun run dev          # Electron with the Vite dev server
bun run dev:web      # browser-only preview with synthetic data, no daemon (port 1420)
bun run check        # type check and lint; must print no errors or warnings
bun test src/lib     # renderer tests; `bun run test` runs everything
bun run format       # bun fmt, configured in bunfig.toml under [fmt]; there is no Prettier
bun run package:dir  # unpacked app in dist/, which the installers package
```

- **The React Compiler is Bun's, and there is no Babel.** Vite still builds and serves the app.
  `vite.react-compiler.ts` is a Vite plugin that passes each component module through
  `Bun.build` with `reactCompiler` before Vite's own transforms, so do not add `memo`, `useMemo`
  or `useCallback` by hand. Two things follow:
  - Vite has to run on Bun's runtime. The `dev`, `dev:web`, `build` and `preview` scripts pass
    `--bun`; under Node the plugin stops with an error.
  - Bun compiles only files it parses as JSX, so the plugin parses `.ts` as TSX to include
    hooks defined there. In a `.ts` file under `src/`, write `value as T` and `<T,>(x) =>`,
    not `<T>value` or `<T>(x) =>`.
- **An edit that reaches a store reloads the dev page.** `vite.store-reload.ts` sends a full
  reload, not a hot update, when a change would evaluate a module in `src/lib/stores/` again:
  the store itself or anything it imports. A second copy of a store would start empty and
  never connect, because the shell's start-up effect does not run again on a hot update.
  Components and styles still update in place.
- **Type checking is `bun check`, not `tsc`.** `bun run typecheck` runs it on `tsconfig.web.json`
  and `tsconfig.node.json`. Inside a package script always pass `--no-script`, or `bun check`
  runs the `check` script and recurses. The `typescript` package is installed only because
  typescript-eslint needs its JavaScript API; nothing type-checks with it.
- **Treat anything `bun run check` prints as yours.**
- **Caches live in `node_modules/.cache/`:** ESLint's, and a hash of the message catalogs so
  Paraglide recompiles only when they change (`scripts/paraglide.ts`). Delete the folder if a
  check looks stale.
- **Main-process tests are `electron/**/*.test.ts`.** A module that imports `electron` cannot
  load under bun, so keep logic you want to test in electron-free modules.

## Layout

| Path | What it holds |
|---|---|
| `electron/main` | The main process. It alone holds the daemon connection and the IPC token. |
| `electron/main/index.ts` | Start-up: single-instance lock, windows, tray, protocol, IPC router. |
| `electron/main/commands/` | One file per feature area, each exporting handlers built with `command(zodShape, fn)` from `define.ts`. `index.ts` assembles `commandTable`. |
| `electron/main/daemon/` | The gRPC client (`@grpc/grpc-js`): `connection.ts` loads `antiwire-proto/proto/antiwire.proto` at runtime, `credentials.ts` reads the token and certificate, `client.ts` makes calls, `stream-pump.ts` batches stream events before they cross IPC, `runtime.ts` lazy-loads the gRPC libraries. |
| `electron/main/dto/` | Converts daemon messages to what the renderer receives, one file per area. A field the daemon adds is not forwarded until a DTO names it. |
| `electron/main/ipc-router.ts` | Refuses calls from any frame that is not the top frame of an app window, and checks the window's role. |
| `electron/main/security.ts`, `protocol.ts` | Navigation and request blocking, and the `app://antiwire` origin the renderer is served from. |
| `electron/main/windows.ts`, `tray.ts`, `menu.ts`, `notifications.ts` | Native windows and shell integration. |
| `electron/main/approved-paths.ts` | Paths the save dialog returned; see [file writes](#rules). |
| `electron/main/client-settings-store.ts` | Client-only preferences (theme, accent, locale, onboarding) on disk. |
| `electron/main/reputation.ts`, `icons/` | Third-party reputation links from a fixed list, and application icons. |
| `electron/preload` | Exposes only `window.antiwire.invoke` and `on`. |
| `shared/` | Code both processes import: `ipc.ts` (commands and events), `project.ts` (repository URL), `window-frame.ts`. |
| `src/routes/` | One page per top-level tab: Dashboard, Records, Firewall, Analytics, Alerts, AI, Capture, Network, Settings, plus the packet Inspector window. |
| `src/shell/` | The app frame around the pages, and the pages it keeps mounted (`kept-pages.ts`). |
| `src/lib/bridge.ts` | The renderer's only path to the main process. |
| `src/lib/api/` | Typed wrappers over the bridge: `daemon.ts` (every daemon command), `normalize.ts`, `client-settings.ts`. |
| `src/lib/stores/` | Long-lived state as `Reactive` classes: `daemon.ts` (the per-second refresh), `client.ts` (preferences), `updates.ts`, icon caches, chart history. |
| `src/lib/state/` | The reactivity primitive: `reactive.ts` (`Reactive`, `useSelector`) and `tracked.ts`. |
| `src/lib/models/` | Pure logic with no React or I/O, most with a test beside them: sorting, validation, settings mapping, chart data, theme, update status. |
| `src/lib/components/` | Components by feature (`dashboard`, `records`, `firewall`, `analytics`, `alerts`, `ai`, `capture`, `network`, `blocklists`, `settings`, `shell`), plus `charts` (hand-written SVG) and `ui` (shared controls). |
| `src/lib/utils/` | Small shared helpers: formatting, errors, clipboard, paths, URLs. |
| `src/lib/preview/` | The synthetic backend behind `bun run dev:web`. |
| `src/lib/i18n/`, `messages/`, `project.inlang/` | Translations: 24 catalogs in `messages/`, compiled by Paraglide into `src/lib/paraglide/` (generated; do not edit). |
| `src/app.css` | Design tokens. |
| `scripts/` | `after-pack.mjs` (flips the Electron fuses), `paraglide.ts`, `i18n/build-locale.mjs`, `update-country-cidrs.mjs`. |
| `resources/icons`, `static/` | Packaged icons, and files served as-is. |

## Rules

- **`shared/ipc.ts` is the only list of commands and events.** Adding a command takes two edits,
  and the compiler rejects a missing one: add the name to `COMMANDS` (and to
  `INSPECTOR_COMMANDS` only if the packet inspector window needs it), then add its handler to
  `commandTable` in `electron/main/commands/index.ts`. Add a mock for it in `src/lib/preview/`
  so the browser preview keeps working; unimplemented commands fail there on purpose.
- **The renderer reaches the main process only through `src/lib/bridge.ts`.** ESLint forbids
  `electron` and `node:*` imports in `src/`.
- **File writes need a path from `pick_save_path`.** Commands that write a user-chosen file
  (`download_capture`, `export_logs`) accept only a destination the native save dialog returned,
  once. Do not add a command that writes to a path taken from the renderer.
- **One state primitive.** Renderer state uses `Reactive` and `useSelector`. Select the
  narrowest slice: the daemon store updates every second.
- **Every catalog has exactly the English keys.** A test enforces it, so add, rename or remove a
  message key in all 24 files under `messages/`.

### Security

The renderer is untrusted: it displays data that came from the network, and a bug there must not
reach the daemon or the disk. Never weaken any of these.

- **Window settings stay locked.** `windows.ts` creates every window with `contextIsolation`,
  `sandbox` and `webSecurity` on, and `nodeIntegration` and `webviewTag` off.
- **The renderer loads only the app.** `security.ts` refuses navigation, new windows, webviews,
  downloads, and every permission except clipboard write and notifications, and cancels any
  request that is not an app resource. Do not add an exception; fetch through the main process.
- **The production content security policy stays strict.** `contentSecurityPolicyFor` in
  `app-url.ts` allows no `unsafe-inline`, no `unsafe-eval` and no remote origin, and requires
  Trusted Types with no policy. Only the dev server gets a looser one.
- **Every command validates its arguments** with a strict zod shape through `command()`. Treat
  each argument as hostile: bound its length, and never pass one to the file system, a child
  process or `shell.openExternal` unchecked.
- **A command never opens a URL from its arguments.** It takes the name of a service from a
  fixed list and the main process builds the URL, as `reputation.ts` does. Links the renderer
  follows go through `openExternalSafely`, which allows only `https`, `http` and `mailto`.
- **The IPC token and certificate never leave the main process.** Do not return them from a
  command, send them in an event, or log them.
- **Do not widen the bridge.** No new preload global, no Node API in the renderer, and no DTO
  that forwards a whole daemon message.
- **Do not change a fuse** in `scripts/after-pack.mjs`. They disable `ELECTRON_RUN_AS_NODE`,
  `NODE_OPTIONS` and the inspector flags, and make the app load only from its
  integrity-checked archive.
- **No dynamic code or markup.** No `eval`, no `new Function`, no script or style loaded from a
  URL, and no `dangerouslySetInnerHTML` or `innerHTML` with text from the daemon or the network.

### Shared homes

Put shared code here instead of copying it:

| Kind of code | Home |
|---|---|
| Used by both the main process and the renderer | `shared/` |
| Buttons, inputs, dialogs, tooltips, lists | `src/lib/components/ui` |
| Charts | `src/lib/components/charts` |
| Formatting and other small helpers | `src/lib/utils` |
| Logic worth testing without React | `src/lib/models` |
| Types of daemon data | `src/lib/types` |
| Daemon message to renderer shape | `electron/main/dto` |
