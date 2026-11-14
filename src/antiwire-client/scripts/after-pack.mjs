// electron-builder `afterPack` hook: hardens the packaged Electron binary by
// flipping its fuses. Runs before code signing, so the signature covers the
// flipped binary.
import { flipFuses, FuseV1Options, FuseVersion } from '@electron/fuses';
import path from 'node:path';

/** The fuse wire every packaged build ships with. */
export const FUSES = {
  version: FuseVersion.V1,
  // No `ELECTRON_RUN_AS_NODE`: the binary cannot be used as a plain Node runtime.
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableCookieEncryption]: true,
  // No `NODE_OPTIONS` or `--inspect`: nothing can inject code into the main process.
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  // The app only loads from its own archive, and the archive must match the hash
  // embedded at build time (macOS and Windows; Linux has no integrity check).
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,
  // The renderer is served from `app://`; `file://` gets no extra powers.
  [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
};

/** Path of the Electron executable (or `.app` bundle) electron-builder just packed. */
function electronBinary(context) {
  const { appOutDir, electronPlatformName, packager } = context;
  const name = packager.appInfo.productFilename;
  switch (electronPlatformName) {
    case 'darwin':
    case 'mas':
      return path.join(appOutDir, `${name}.app`);
    case 'win32':
      return path.join(appOutDir, `${name}.exe`);
    default:
      return path.join(appOutDir, packager.executableName);
  }
}

export default async function afterPack(context) {
  const binary = electronBinary(context);
  await flipFuses(binary, {
    ...FUSES,
    // Flipping invalidates the macOS ad-hoc signature, which arm64 requires to
    // launch; re-sign ad hoc (a real signing step later replaces it).
    resetAdHocDarwinSignature: context.electronPlatformName === 'darwin',
  });
  console.log(`[after-pack] flipped Electron fuses in ${binary}`);
}
