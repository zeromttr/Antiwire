import { beforeAll, describe, expect, mock, test } from 'bun:test';
import { loadMessages } from '#lib/i18n/messages.ts';
import type { UpdateStatus } from '#lib/types/index.ts';
import { UpdatesStore, type UpdatesClient } from './updates';

function status(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    state: 'up_to_date',
    currentVersion: '0.2.0',
    availableVersion: '',
    notes: '',
    detail: '',
    channel: 'stable',
    lastCheckedAt: 0,
    checkError: '',
    clientVersion: '0.2.0',
    ...overrides,
  };
}

function store(client: Partial<UpdatesClient> = {}) {
  const full: UpdatesClient = {
    getUpdateStatus: mock(async () => status()),
    checkForUpdates: mock(async () => status({ lastCheckedAt: 1_700_000_000 })),
    installUpdate: mock(async () => ({ success: true, message: '' })),
    ...client,
  };
  return { updates: new UpdatesStore(full), client: full };
}

beforeAll(async () => {
  await loadMessages('en');
});

describe('UpdatesStore', () => {
  test('a manual check replaces the status with the daemon’s answer', async () => {
    const { updates, client } = store();
    await updates.check();
    expect(client.checkForUpdates).toHaveBeenCalledTimes(1);
    expect(updates.status?.lastCheckedAt).toBe(1_700_000_000);
    expect(updates.checking).toBe(false);
    expect(updates.checkFailure).toBe('');
  });

  test('a second click while checking waits for the first', async () => {
    let finish: (value: UpdateStatus) => void = () => {};
    const { updates, client } = store({
      checkForUpdates: mock(
        () =>
          new Promise<UpdateStatus>((resolve) => {
            finish = resolve;
          }),
      ),
    });
    const first = updates.check();
    expect(updates.checking).toBe(true);
    await updates.check();
    expect(client.checkForUpdates).toHaveBeenCalledTimes(1);
    finish(status());
    await first;
    expect(updates.checking).toBe(false);
  });

  test('a check that cannot reach the daemon keeps the status and says why', async () => {
    const { updates } = store({
      checkForUpdates: mock(async () => {
        throw new Error('daemon unavailable');
      }),
    });
    await updates.refresh();
    const before = updates.status;
    await updates.check();
    expect(updates.status).toBe(before);
    expect(updates.checkFailure).toContain('daemon unavailable');
  });

  test('installs the available version and closes the dialog', async () => {
    const { updates, client } = store({
      getUpdateStatus: mock(async () => status({ state: 'available', availableVersion: '0.3.0' })),
    });
    await updates.refresh();
    updates.setInstallDialogOpen(true);
    await updates.install();
    expect(client.installUpdate).toHaveBeenCalledWith('0.3.0');
    expect(updates.installDialogOpen).toBe(false);
    expect(updates.installSubmitting).toBe(false);
  });

  test('keeps the dialog open with the daemon’s reason when it refuses, until reopened', async () => {
    const { updates } = store({
      getUpdateStatus: mock(async () => status({ state: 'available', availableVersion: '0.3.0' })),
      installUpdate: mock(async () => ({ success: false, message: 'version 0.3.0 is gone' })),
    });
    await updates.refresh();
    updates.setInstallDialogOpen(true);
    await updates.install();
    expect(updates.installDialogOpen).toBe(true);
    expect(updates.installError).toBe('version 0.3.0 is gone');
    updates.setInstallDialogOpen(false);
    updates.setInstallDialogOpen(true);
    expect(updates.installError).toBe('');
  });

  test('installs nothing when no release is available', async () => {
    const { updates, client } = store();
    await updates.refresh();
    await updates.install();
    expect(client.installUpdate).not.toHaveBeenCalled();
  });
});
