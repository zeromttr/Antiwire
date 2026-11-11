import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ClientSettingsStore,
  clientSettingsPatchSchema,
  sanitizeClientSettings,
} from './client-settings-store';

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'antiwire-settings-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('ClientSettingsStore', () => {
  it('starts empty and merges patches', async () => {
    const store = new ClientSettingsStore(path.join(dir, 'nested', 'client-settings.json'));
    expect(await store.read()).toEqual({});
    expect(await store.update({ theme: 'dark' })).toEqual({ theme: 'dark' });
    expect(await store.update({ accentColorId: '#AABBCC', onboardingDone: true })).toEqual({
      theme: 'dark',
      accentColorId: '#AABBCC',
      onboardingDone: true,
    });
    expect(await store.read()).toEqual({
      theme: 'dark',
      accentColorId: '#AABBCC',
      onboardingDone: true,
    });
  });

  it('serializes concurrent writes', async () => {
    const store = new ClientSettingsStore(path.join(dir, 's.json'));
    await Promise.all([
      store.update({ theme: 'light' }),
      store.update({ locale: 'de' }),
      store.update({ onboardingDone: true }),
    ]);
    expect(await store.read()).toEqual({ theme: 'light', locale: 'de', onboardingDone: true });
  });

  it('ignores corrupt files and unknown or invalid keys', async () => {
    const file = path.join(dir, 's.json');
    fs.writeFileSync(file, '{not json');
    expect(await new ClientSettingsStore(file).read()).toEqual({});
    expect(
      sanitizeClientSettings({ theme: 'neon', locale: 'pt-BR', token: 'x', onboardingDone: 'yes' }),
    ).toEqual({ locale: 'pt-BR' });
  });

  it('falls back to the legacy file until the first write', async () => {
    const file = path.join(dir, 'new', 's.json');
    const legacy = path.join(dir, 'legacy.json');
    fs.writeFileSync(
      legacy,
      JSON.stringify({ theme: 'dark', themeColorId: 'dusk', onboardingDone: true }),
    );
    const store = new ClientSettingsStore(file, legacy);
    expect(await store.read()).toEqual({ theme: 'dark', onboardingDone: true });
    expect(await store.update({ locale: 'de' })).toEqual({
      theme: 'dark',
      onboardingDone: true,
      locale: 'de',
    });
    fs.writeFileSync(legacy, JSON.stringify({ theme: 'light' }));
    expect(await store.read()).toEqual({ theme: 'dark', onboardingDone: true, locale: 'de' });
  });

  it('does not fall back to the legacy file when the current one is corrupt', async () => {
    const file = path.join(dir, 's.json');
    const legacy = path.join(dir, 'legacy.json');
    fs.writeFileSync(file, '{not json');
    fs.writeFileSync(legacy, JSON.stringify({ theme: 'dark' }));
    expect(await new ClientSettingsStore(file, legacy).read()).toEqual({});
  });

  it('rejects unknown keys in a patch', () => {
    expect(clientSettingsPatchSchema.safeParse({ theme: 'dark', other: 1 }).success).toBe(false);
    expect(clientSettingsPatchSchema.safeParse({ accentColorId: 'x'.repeat(40) }).success).toBe(
      false,
    );
  });
});
